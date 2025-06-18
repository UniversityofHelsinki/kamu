"""
Membership views for the UI.
"""

import datetime
from typing import Any, TypeVar
from uuid import uuid4

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import PermissionDenied
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
    MembershipMassCreateForm,
)
from kamu.models.identity import Identifier, Identity
from kamu.models.membership import Membership
from kamu.models.role import Role
from kamu.models.token import TimeLimitError, Token
from kamu.utils.audit import AuditLog
from kamu.utils.identity import import_identity
from kamu.utils.membership import (
    add_missing_requirement_messages,
    claim_membership,
    get_expiring_memberships,
    get_mass_invite_limit,
    get_memberships_requiring_approval,
)
from kamu.views.identity import IdentitySearchView

audit_log = AuditLog()


MembershipFormType = TypeVar(
    "MembershipFormType", MembershipCreateForm, MembershipEmailCreateForm, MembershipMassCreateForm
)


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
                invite_text=self.object.invite_text,
                lang=self.object.invite_language,
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

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """
        Add date limit to context.
        """
        context = super().get_context_data(**kwargs)
        context["expiring_date_limit"] = getattr(settings, "EXPIRING_LIMIT_DAYS", 30)
        return context

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
            if any(obj.get("mail") == email for obj in context["ldap_results"]):
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


class BaseMembershipInviteView(LoginRequiredMixin, CreateView[Membership, MembershipFormType]):
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

    def form_valid(self, form: MembershipFormType) -> HttpResponse:
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

    def form_valid(self, form: MembershipFormType) -> HttpResponse:
        """
        Create identity and membership.

        If identity already exists with the same uid or fpic, use it instead.
        """
        uid = self.kwargs.get("uid")
        inviter = self.request.user if self.request.user.is_authenticated else None
        identity = import_identity(uid, request=self.request)
        if not identity or not inviter:
            raise PermissionDenied
        form.instance.identity = identity
        form.instance.role = get_object_or_404(Role, pk=self.kwargs.get("role_pk"))
        form.instance.inviter = inviter
        if form.instance.role.is_approver(user=inviter):
            form.instance.approver = inviter
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

    def form_valid(self, form: MembershipFormType) -> HttpResponse:
        """
        Set role and other data to the membership.
        """
        form.instance.identity = None
        form.instance.role = get_object_or_404(Role, pk=self.kwargs.get("role_pk"))
        user = self.request.user if self.request.user.is_authenticated else None
        if not user or not form.instance.invite_email_address:
            raise PermissionDenied
        invite_email_address = form.instance.invite_email_address
        invite_text = form.instance.invite_text
        invite_language = form.instance.invite_language
        form.instance.inviter = user
        if form.instance.role.is_approver(user=user):
            form.instance.approver = user
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
            f"Invited {membership.invite_email_address} to role {membership.role}",
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


class MembershipMassInviteView(BaseMembershipInviteView):
    """
    Invite multiple members.
    """

    form_class = MembershipMassCreateForm

    def get_form_kwargs(self) -> dict[str, Any]:
        """
        Add invite limit to form kwargs.
        """
        kwargs = super().get_form_kwargs()
        kwargs["invite_limit"] = get_mass_invite_limit(self.request.user)
        return kwargs

    def find_identity(self, info: dict[str, str]) -> Identity | None:
        """
        Find identity by fpic, email or phone.
        """
        fpic = info.get("fpic")
        fpic_identity = (
            Identity.objects.filter(
                Q(fpic=fpic)
                | Q(identifiers__type=Identifier.Type.FPIC, identifiers__value=fpic, identifiers__deactivated_at=None)
            )
            .distinct()
            .first()
            if fpic
            else None
        )
        email = info.get("email")
        email_identity = (
            Identity.objects.filter(email_addresses__address__iexact=email, email_addresses__verified=True).first()
            if email
            else None
        )
        phone = info.get("phone")
        phone_identity = (
            Identity.objects.filter(phone_numbers__number=phone, phone_numbers__verified=True).first()
            if phone
            else None
        )
        if fpic_identity and email_identity and fpic_identity != email_identity:
            messages.add_message(
                self.request,
                messages.WARNING,
                _(
                    "Finnish personal identity code {fpic} and email address {email} are registered to different "
                    "identities."
                ).format(fpic=fpic, email=email),
            )
            return None
        if fpic_identity and phone_identity and fpic_identity != phone_identity:
            messages.add_message(
                self.request,
                messages.WARNING,
                _(
                    "Finnish personal identity code {fpic} and phone number {phone} are registered to different "
                    "identities."
                ).format(fpic=fpic, phone=phone),
            )
            return None
        if email_identity and phone_identity and email_identity != phone_identity:
            messages.add_message(
                self.request,
                messages.WARNING,
                _("Email address {email} and phone number {phone} are registered to different identities.").format(
                    email=email, phone=phone
                ),
            )
            return None
        return fpic_identity or email_identity or phone_identity

    def form_valid(self, form: MembershipFormType) -> HttpResponse:
        """
        Parse invited users, role parameters.
        Either show preview or add memberships and send invites.
        """
        form.instance.identity = None
        form.instance.role = get_object_or_404(Role, pk=self.kwargs.get("role_pk"))
        user = self.request.user if self.request.user.is_authenticated else None
        if not user:
            raise PermissionDenied
        invite_text = form.instance.invite_text
        invite_language = form.instance.invite_language
        form.instance.inviter = user
        if form.instance.role.is_approver(user=user):
            form.instance.approver = user
        invitees = form.cleaned_data["invited"]
        to_be_invited = []
        to_be_added = []
        for invited in invitees:
            if not invited or not isinstance(invited, dict):
                continue
            identity = self.find_identity(invited)
            email = invited.get("email")
            if identity:
                to_be_added.append(identity)
            elif email:
                to_be_invited.append(email)
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
            context["to_be_invited"] = to_be_invited
            context["to_be_added"] = to_be_added
            context["preview_subject"] = subject
            context["preview_message"] = message
            return self.render_to_response(context)
        invited_list = []
        added_list = []
        for identity in to_be_added:
            form.instance.pk = None
            form.instance.identity = identity
            form.instance.invite_email_address = None
            form.instance.identifier = uuid4()
            membership = form.save()
            audit_log.info(
                f"Membership to {membership.role} added to identity: {membership.identity}",
                category="membership",
                action="create",
                outcome="success",
                request=self.request,
                objects=[membership, membership.identity, membership.role],
                log_to_db=True,
            )
            send_add_email(membership)
            added_list.append(identity.display_name())
        for email in to_be_invited:
            form.instance.pk = None
            form.instance.identity = None
            form.instance.invite_email_address = email
            form.instance.identifier = uuid4()
            membership = form.save()
            audit_log.info(
                f"Invited {membership.invite_email_address} to role {membership.role}",
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
                address=email,
                invite_text=invite_text,
                lang=invite_language,
                request=self.request,
            )
            invited_list.append(email)
        if invited_list:
            messages.add_message(
                self.request,
                messages.INFO,
                _("Invite email sent to following addresses: {0}").format(", ".join(invited_list)),
            )
        if added_list:
            messages.add_message(
                self.request, messages.INFO, _("Added following identities: {0}").format(", ".join(added_list))
            )
        return redirect("role-detail", pk=form.instance.role.pk)
