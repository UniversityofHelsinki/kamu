"""
Membership views for the UI.
"""

import datetime
from typing import Any

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import PermissionDenied, ValidationError
from django.db.models import Q, QuerySet
from django.http import HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.utils.translation import gettext as _
from django.views.decorators.csrf import csrf_protect
from django.views.generic import DetailView, ListView, View
from django.views.generic.edit import CreateView, UpdateView

from kamu.connectors.email import (
    create_invite_message,
    send_add_email,
    send_invite_email,
)
from kamu.connectors.ldap import LDAP_SIZELIMIT_EXCEEDED, ldap_search
from kamu.forms.membership import (
    MembershipCreateForm,
    MembershipEditForm,
    MembershipEmailCreateForm,
)
from kamu.models.identity import EmailAddress, Identifier, Identity
from kamu.models.membership import Membership
from kamu.models.role import Role
from kamu.models.token import TimeLimitError, Token
from kamu.utils.audit import AuditLog
from kamu.utils.membership import (
    add_missing_requirement_messages,
    claim_membership,
    get_expiring_memberships,
    get_memberships_requiring_approval,
)
from kamu.validators.identity import validate_fpic
from kamu.views.identity import IdentitySearchView

audit_log = AuditLog()


class MembershipJoinView(LoginRequiredMixin, CreateView[Membership, MembershipCreateForm]):
    """
    View for joining a role.
    """

    model = Membership
    form_class = MembershipCreateForm
    template_name = "membership/membership_form.html"

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """
        Requires approver permissions for the role.
        Redirects user to role details if they don't have an identity.
        Redirects user to membership details if they already have this role.
        """
        user = self.request.user
        if not user.is_authenticated:
            raise PermissionDenied
        role = get_object_or_404(Role, pk=self.kwargs.get("role_pk"))
        if not role.is_approver(user):
            raise PermissionDenied
        if not Identity.objects.filter(user=user).exists():
            messages.add_message(request, messages.WARNING, _("You need to create an identity first."))
            return redirect("role-detail", pk=kwargs.pop("role_pk"))
        try:
            membership = Membership.objects.get(identity=user.identity, role=role, status=Membership.Status.ACTIVE)
            messages.add_message(request, messages.WARNING, _("You are already a member of this role."))
            return redirect("membership-detail", pk=membership.pk)
        except Membership.DoesNotExist:
            pass
        return super().get(request, *args, **kwargs)

    def get_initial(self) -> dict[str, Any]:
        """
        Adds initial values to start_date and expire_date.
        """
        role = get_object_or_404(Role, pk=self.kwargs.get("role_pk"))
        start_date = timezone.now().date()
        expire_date = timezone.now().date() + datetime.timedelta(days=role.maximum_duration)
        return {
            "start_date": start_date,
            "expire_date": expire_date,
        }

    def get_form_kwargs(self) -> dict[str, Any]:
        """
        Add role to form kwargs.
        """
        kwargs = super().get_form_kwargs()
        kwargs["role"] = get_object_or_404(Role, pk=self.kwargs.get("role_pk"))
        return kwargs

    def form_valid(self, form: MembershipCreateForm) -> HttpResponse:
        """
        Set identity and role and other information for the membership.
        """
        user = self.request.user
        if not user.is_authenticated:
            raise PermissionDenied
        role = get_object_or_404(Role, pk=self.kwargs.get("role_pk"))
        if not user.identity or not role.is_approver(user):
            raise PermissionDenied
        form.instance.identity = user.identity
        form.instance.role = role
        form.instance.approver = user
        form.instance.inviter = user
        valid = super().form_valid(form)
        if self.object:
            audit_log.info(
                f"Membership to {self.object.role} added to identity: {self.object.identity}",
                category="membership",
                action="create",
                outcome="success",
                request=self.request,
                objects=[self.object, self.object.identity, self.object.role],
                log_to_db=True,
            )
        return valid


class MembershipDetailView(LoginRequiredMixin, DetailView[Membership]):
    """
    View for membership details.
    """

    model = Membership
    template_name = "membership/membership_detail.html"

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """
        Log viewing membership information.
        """
        get = super().get(request, *args, **kwargs)
        audit_log.info(
            "Read membership information",
            category="membership",
            action="read",
            outcome="success",
            request=self.request,
            objects=[self.object, self.object.role, self.object.identity],
        )
        if self.object.identity:
            missing_requirements = self.object.get_missing_requirements()
            if missing_requirements:
                add_missing_requirement_messages(self.request, missing_requirements, self.object.identity)
        return get

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """
        Add approver and inviter permission info to context.
        """
        context = super().get_context_data(**kwargs)
        user = self.request.user
        if not user.is_authenticated:
            raise PermissionDenied
        if self.object.role.is_approver(user):
            context["is_approver"] = True
        if self.object.role.is_inviter(user):
            context["is_inviter"] = True
        return context

    def get_queryset(self) -> QuerySet[Membership]:
        """
        Limit membership details to a member, approvers, inviters and owners.
        """
        user = self.request.user
        if not user.is_authenticated:
            raise PermissionDenied
        groups = user.groups.all()
        queryset = Membership.objects.all()
        if not user.is_superuser:
            queryset = queryset.filter(
                Q(role__approvers__in=groups)
                | Q(role__inviters__in=groups)
                | Q(role__owner=user)
                | Q(identity__user=user)
            ).distinct()
        return queryset.prefetch_related("identity", "role")

    def _approve_membership(self, request: HttpRequest) -> None:
        """
        Approve membership, if user is approver and membership is not approved.
        """
        if not self.request.user.is_authenticated or not self.object.role.is_approver(self.request.user):
            raise PermissionDenied
        if not self.object.approver:
            self.object.approver = self.request.user
            self.object.set_status()
            self.object.save()
            audit_log.info(
                f"Membership to {self.object.role} approved for identity: {self.object.identity}",
                category="membership",
                action="update",
                outcome="success",
                request=self.request,
                objects=[self.object, self.object.identity, self.object.role],
                log_to_db=True,
            )
            messages.add_message(request, messages.INFO, _("Membership approved."))

    def _resend_invite(self, request: HttpRequest) -> None:
        """
        Resend invite email, if user is inviter.
        """
        if (
            not self.request.user.is_authenticated
            or not self.object.role.is_inviter(self.request.user)
            or not self.object.invite_email_address
        ):
            raise PermissionDenied
        try:
            token = Token.objects.create_invite_token(membership=self.object)
            if send_invite_email(
                membership=self.object,
                token=token,
                address=self.object.invite_email_address,
                invite_text="",
                request=self.request,
            ):
                messages.add_message(request, messages.INFO, _("Invite email sent."))
            else:
                messages.add_message(request, messages.ERROR, _("Could not send invite email."))
        except TimeLimitError:
            messages.add_message(
                self.request,
                messages.WARNING,
                _("Tried to send a new invite too soon. Please try again in one minute."),
            )

    def _end_membership(self, request: HttpRequest) -> None:
        """
        Set membership to end after today, if user is approver or the identity user.
        """
        if not self.request.user.is_authenticated:
            raise PermissionDenied
        if not self.object.role.is_approver(self.request.user) and (
            not self.object.identity or self.object.identity.user != self.request.user
        ):
            raise PermissionDenied
        if self.object.expire_date > timezone.now().date():
            self.object.expire_date = timezone.now().date()
            self.object.save()
            audit_log.info(
                f"Membership to {self.object.role} ended for identity: {self.object.identity}",
                category="membership",
                action="update",
                outcome="success",
                request=self.request,
                objects=[self.object, self.object.identity, self.object.role],
                log_to_db=True,
            )
            messages.add_message(request, messages.INFO, _("Membership set to end today."))

    @method_decorator(csrf_protect)
    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """
        Check for role approval.
        """
        self.object = self.get_object()
        if not self.request.user.is_authenticated:
            raise PermissionDenied
        if "approve_membership" in self.request.POST:
            self._approve_membership(request)
        if "resend_invite" in self.request.POST:
            self._resend_invite(request)
        if "end_membership" in self.request.POST:
            self._end_membership(request)
        return redirect("membership-detail", pk=self.object.pk)


class MembershipUpdateView(LoginRequiredMixin, UpdateView[Membership, MembershipEditForm]):
    """
    Update membership information.
    """

    model = Membership
    form_class = MembershipEditForm
    template_name = "membership/membership_edit_form.html"

    def form_valid(self, form: MembershipEditForm) -> HttpResponse:
        """
        Edit membership data and update approver.
        """
        user = self.request.user if self.request.user.is_authenticated else None
        if not user or not form.instance.role.is_approver(user):
            raise PermissionDenied
        form.instance.approver = user
        valid = super().form_valid(form)
        if self.object:
            audit_log.info(
                f"Membership modified, role: {self.object.role}, identity: {self.object.identity}",
                category="membership",
                action="update",
                outcome="success",
                request=self.request,
                objects=[self.object, self.object.identity, self.object.role],
                log_to_db=True,
            )
            messages.add_message(self.request, messages.INFO, _("Membership updated."))
        return valid


class MembershipListBaseView(LoginRequiredMixin, ListView[Membership]):
    """
    Base view for membership list.
    """

    model = Membership

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """
        Log listing membership information.
        """
        get = super().get(request, *args, **kwargs)
        audit_log.info(
            "List membership information",
            category="membership",
            action="read",
            outcome="success",
            request=self.request,
        )
        return get


class MembershipApprovalListView(MembershipListBaseView):
    """
    List memberships that require approval.
    """

    template_name = "membership/membership_approval_list.html"

    def get_queryset(self) -> QuerySet[Membership]:
        """
        Include only memberships that require approval.
        """
        if self.request.user.is_authenticated:
            return get_memberships_requiring_approval(self.request.user, include_inviters=True)
        return Membership.objects.none()


class MembershipExpiringListView(MembershipListBaseView):
    """
    List expiring memberships.
    """

    template_name = "membership/membership_expiring_list.html"

    def get_queryset(self) -> QuerySet[Membership]:
        """
        Include only memberships expiring in the next EXPIRING_LIMIT_DAYS (default 30) days.
        """
        if self.request.user.is_authenticated:
            return get_expiring_memberships(self.request.user, include_inviters=True)
        return Membership.objects.none()


class MembershipInviteIdentitySearch(IdentitySearchView):
    """
    Subclass of IdentitySearchView for adding identities to role.
    """

    template_name = "membership/membership_invite_identity.html"

    @staticmethod
    def search_ldap() -> bool:
        """
        Enable LDAP search.
        """
        return getattr(settings, "LDAP_SEARCH_FOR_INVITES", True)

    def _check_email(self, context: dict[str, Any], email: str | None) -> bool:
        """
        Check if email is found in the registry.
        """
        if not email:
            return False
        if context.get("ldap_results") is not None:
            if any(obj["mail"] == email for obj in context["ldap_results"]):
                return True
        return Identity.objects.filter(email_addresses__address__iexact=email).exists()

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """
        Add form and role to the context data.
        Add searched email and information if it has been found.
        """
        context = super().get_context_data(**kwargs)
        email = self.request.POST.get("email")
        context["email_found"] = self._check_email(context, email)
        self.request.session["invitation_email_address"] = email
        context["role"] = get_object_or_404(Role, pk=self.kwargs.get("role_pk"))
        return context


class BaseMembershipInviteView(
    LoginRequiredMixin, CreateView[Membership, MembershipCreateForm | MembershipEmailCreateForm]
):
    """
    Base view for inviting a user to a role.
    """

    model = Membership
    template_name = "membership/membership_invite.html"

    def get_initial(self) -> dict[str, Any]:
        """
        Adds initial values to start_date and expire_date.
        """
        role = get_object_or_404(Role, pk=self.kwargs.get("role_pk"))
        start_date = timezone.now().date()
        expire_date = timezone.now().date() + datetime.timedelta(days=role.maximum_duration)
        return {
            "start_date": start_date,
            "expire_date": expire_date,
        }

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """
        Add role to context.
        """
        context = super().get_context_data(**kwargs)
        context["role"] = get_object_or_404(Role, pk=self.kwargs.get("role_pk"))
        return context

    def get_form_kwargs(self) -> dict[str, Any]:
        """
        Add role to form kwargs.
        """
        kwargs = super().get_form_kwargs()
        kwargs["role"] = get_object_or_404(Role, pk=self.kwargs.get("role_pk"))
        return kwargs


class MembershipInviteView(BaseMembershipInviteView):
    """
    Invite view for identities found in the registry.
    """

    form_class = MembershipCreateForm

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """
        Add identity to context.
        """
        context = super().get_context_data(**kwargs)
        context["identity"] = get_object_or_404(Identity, pk=self.kwargs.get("identity_pk"))
        return context

    def form_valid(self, form: MembershipCreateForm | MembershipEmailCreateForm) -> HttpResponse:
        """
        Set role and other data to the membership.
        """
        form.instance.identity = get_object_or_404(Identity, pk=self.kwargs.get("identity_pk"))
        form.instance.role = get_object_or_404(Role, pk=self.kwargs.get("role_pk"))
        user = self.request.user if self.request.user.is_authenticated else None
        if not user:
            raise PermissionDenied
        form.instance.inviter = user
        if form.instance.role.is_approver(user=user):
            form.instance.approver = user
        valid = super().form_valid(form)
        if self.object:
            audit_log.info(
                f"Membership to {self.object.role} added to identity: {self.object.identity}",
                category="membership",
                action="create",
                outcome="success",
                request=self.request,
                objects=[self.object, self.object.identity, self.object.role],
                log_to_db=True,
            )
            send_add_email(self.object)
        return valid


class MembershipInviteLdapView(BaseMembershipInviteView):
    """
    Invite view for identities found in the LDAP.
    """

    form_class = MembershipCreateForm

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """
        Redirect user to role invite view if identity is found with uid.
        """
        self.object = None
        context = self.get_context_data(**kwargs)
        if "identity" in context:
            return redirect("role-invite-details", role_pk=context["role"].pk, identity_pk=context["identity"].pk)
        return self.render_to_response(context)

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """
        Add user to context. Add identity to context if found.
        """
        context = super().get_context_data(**kwargs)
        uid = self.kwargs.get("uid")
        try:
            ldap_user = ldap_search(
                search_filter="(uid={})", search_values=[uid], ldap_attributes=["uid", "cn", "mail"]
            )
        except LDAP_SIZELIMIT_EXCEEDED:
            raise PermissionDenied
        if not ldap_user or len(ldap_user) != 1:
            raise PermissionDenied
        user = ldap_user[0]
        try:
            identity = Identity.objects.get(uid=user["uid"])
            context["identity"] = identity
        except Identity.DoesNotExist:
            pass
        except Identity.MultipleObjectsReturned:
            raise PermissionDenied
        context["ldapuser"] = user
        return context

    @staticmethod
    def _parse_fpic(user: dict) -> str | None:
        """
        Parse fpic from user.
        """
        if "schacPersonalUniqueID" in user:
            fpic = user["schacPersonalUniqueID"].rsplit(":", 1)[1]
            try:
                validate_fpic(fpic)
                return fpic
            except ValidationError:
                return None
        return None

    def _create_identity_from_ldap(self, user: dict) -> Identity:
        """
        Create identity from LDAP attributes.

        Use get_or_create to create eppn and fpic identifiers, to avoid duplicates.
        """
        identity = Identity.objects.create(
            uid=user["uid"],
            given_names=user["givenName"],
            given_names_verification=Identity.VerificationMethod.EXTERNAL,
            surname=user["sn"],
            surname_verification=Identity.VerificationMethod.EXTERNAL,
        )
        audit_log.info(
            "Identity created.",
            category="identity",
            action="create",
            outcome="success",
            request=self.request,
            objects=[identity],
            log_to_db=True,
        )
        if "mail" in user:
            email_object = EmailAddress.objects.create(address=user["mail"], identity=identity)
            audit_log.info(
                f"Email address added to identity { identity }",
                category="email_address",
                action="create",
                outcome="success",
                request=self.request,
                objects=[email_object, identity],
                log_to_db=True,
            )
        if "schacDateOfBirth" in user:
            identity.date_of_birth = datetime.datetime.strptime(user["schacDateOfBirth"], "%Y%m%d").date()
            identity.date_of_birth_verification = Identity.VerificationMethod.EXTERNAL
        if "preferredLanguage" in user and user["preferredLanguage"] in [k for k, v in settings.LANGUAGES]:
            identity.preferred_language = user["preferredLanguage"]
        fpic = self._parse_fpic(user)
        if fpic:
            identity.fpic = fpic
            identity.fpic_verification = Identity.VerificationMethod.EXTERNAL
        identity.save()
        identifier, created = Identifier.objects.get_or_create(
            type=Identifier.Type.EPPN,
            value=f"{user['uid']}{settings.LOCAL_EPPN_SUFFIX}",
            identity=identity,
            deactivated_at=None,
        )
        if created:
            audit_log.info(
                f"Linked { identifier.type } identifier to identity { identity }",
                category="identifier",
                action="create",
                outcome="success",
                request=self.request,
                objects=[identifier, identity],
                log_to_db=True,
            )
        if fpic:
            Identifier.objects.get_or_create(
                type=Identifier.Type.FPIC, value=fpic, identity=identity, deactivated_at=None
            )
        return identity

    def _check_existing_identity(self, user: dict) -> Identity | None:
        """
        Check if identity already exists.
        - uid or fpic
        - Identifier with type eppn or fpic
        """
        try:
            return Identity.objects.get(uid=user["uid"])
        except Identity.DoesNotExist:
            pass
        try:
            return Identifier.objects.get(
                type=Identifier.Type.EPPN,
                value=f"{user['uid']}{settings.LOCAL_EPPN_SUFFIX}",
                deactivated_at=None,
            ).identity
        except Identifier.DoesNotExist:
            pass
        fpic = self._parse_fpic(user)
        if fpic:
            try:
                return Identity.objects.get(fpic=fpic)
            except Identity.DoesNotExist:
                pass
            try:
                return Identifier.objects.get(
                    type=Identifier.Type.FPIC,
                    value=fpic,
                    deactivated_at=None,
                ).identity
            except Identifier.DoesNotExist:
                pass
        return None

    def form_valid(self, form: MembershipCreateForm | MembershipEmailCreateForm) -> HttpResponse:
        """
        Create identity and membership.

        If identity already exists with the same uid or fpic, use it instead.
        """
        uid = self.kwargs.get("uid")
        try:
            ldap_user = ldap_search(
                search_filter="(uid={})",
                search_values=[uid],
                ldap_attributes=[
                    "uid",
                    "givenName",
                    "sn",
                    "mail",
                    "schacDateOfBirth",
                    "preferredLanguage",
                    "schacPersonalUniqueID",
                ],
            )
        except LDAP_SIZELIMIT_EXCEEDED:
            raise PermissionDenied
        if not ldap_user or len(ldap_user) != 1:
            raise PermissionDenied
        user = ldap_user[0]
        identity = self._check_existing_identity(user)
        if not identity:
            identity = self._create_identity_from_ldap(user)
        form.instance.identity = identity
        form.instance.role = get_object_or_404(Role, pk=self.kwargs.get("role_pk"))
        inviter = self.request.user if self.request.user.is_authenticated else None
        if not inviter:
            raise PermissionDenied
        form.instance.inviter = inviter
        if form.instance.role.is_approver(user=inviter):
            form.instance.approver = inviter
        valid = super().form_valid(form)
        if self.object:
            audit_log.info(
                f"Membership to {self.object.role.identifier} added to identity: {self.object.identity}",
                category="membership",
                action="create",
                outcome="success",
                request=self.request,
                objects=[self.object, self.object.identity, self.object.role],
                log_to_db=True,
            )
            send_add_email(self.object)
        return valid


class MembershipInviteEmailView(BaseMembershipInviteView):
    """
    View for inviting a user to a role with an email-address.
    """

    form_class = MembershipEmailCreateForm

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """
        Add email to context.
        """
        context = super().get_context_data(**kwargs)
        context["email"] = self.request.session.get("invitation_email_address")
        if not context["email"]:
            raise PermissionDenied
        return context

    def get_form_kwargs(self) -> dict[str, Any]:
        """
        Add email to form kwargs.
        """
        kwargs = super().get_form_kwargs()
        kwargs["email"] = self.request.session.get("invitation_email_address")
        return kwargs

    def form_valid(self, form: MembershipCreateForm | MembershipEmailCreateForm) -> HttpResponse:
        """
        Set role and other data to the membership.
        """
        form.instance.identity = None
        form.instance.role = get_object_or_404(Role, pk=self.kwargs.get("role_pk"))
        user = self.request.user if self.request.user.is_authenticated else None
        if not user or not form.instance.invite_email_address:
            raise PermissionDenied
        invite_email_address = form.instance.invite_email_address
        invite_text = form.cleaned_data["invite_text"]
        form.instance.inviter = user
        if form.instance.role.is_approver(user=user):
            form.instance.approver = user
        if hasattr(form, "cleaned_data") and "invite_language" in form.cleaned_data:
            invite_language = form.cleaned_data["invite_language"]
        else:
            invite_language = "en"
        if "preview_message" in self.request.POST:
            subject, message = create_invite_message(
                role=form.instance.role,
                inviter=form.instance.inviter.get_full_name(),
                token="...",
                invite_text=invite_text,
                lang=invite_language,
                request=self.request,
            )
            context = self.get_context_data()
            context["preview_subject"] = subject
            context["preview_message"] = message
            return self.render_to_response(context)
        membership = form.save()
        audit_log.info(
            f"Invited {membership.invite_email_address} to role {membership.role.identifier}",
            category="membership",
            action="create",
            outcome="success",
            request=self.request,
            objects=[membership, membership.role],
            log_to_db=True,
        )
        token = Token.objects.create_invite_token(membership=membership)
        send_invite_email(
            membership=membership,
            token=token,
            address=invite_email_address,
            invite_text=invite_text,
            lang=invite_language,
            request=self.request,
        )
        messages.add_message(self.request, messages.INFO, _("Invite email sent."))
        return redirect("membership-detail", pk=membership.pk)


class MembershipClaimView(LoginRequiredMixin, View):
    """
    Claim an invitation to a role membership.
    """

    def get(self, request: HttpRequest) -> HttpResponse:
        user = self.request.user
        if not user.is_authenticated:
            raise PermissionDenied
        if not hasattr(user, "identity"):
            identity = Identity.objects.create(user=user, given_names=user.first_name, surname=user.last_name)
            audit_log.info(
                "Identity created.",
                category="identity",
                action="create",
                outcome="success",
                request=self.request,
                objects=[identity],
                log_to_db=True,
            )
        membership_pk = claim_membership(request, user.identity)
        if membership_pk == -1:
            return redirect("front-page")
        return redirect("membership-detail", pk=membership_pk)
