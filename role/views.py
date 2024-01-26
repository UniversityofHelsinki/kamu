"""
Role app views for the UI.
"""

import datetime
from typing import Any

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import PermissionDenied, ValidationError
from django.db.models import Q, QuerySet
from django.http import HttpRequest, HttpResponse, HttpResponseBase
from django.shortcuts import get_object_or_404, redirect
from django.utils import timezone
from django.utils.translation import get_language
from django.utils.translation import gettext as _
from django.views.generic import DetailView, ListView, View
from django.views.generic.edit import CreateView

from base.connectors.email import send_invite_email
from base.connectors.ldap import LDAP_SIZELIMIT_EXCEEDED, ldap_search
from base.models import Token
from identity.models import EmailAddress, Identifier, Identity
from identity.validators import validate_fpic
from identity.views import IdentitySearchView
from role.forms import MembershipCreateForm, MembershipEmailCreateForm, TextSearchForm
from role.models import Membership, Role
from role.utils import claim_membership


class RoleJoinView(LoginRequiredMixin, CreateView[Membership, MembershipCreateForm]):
    """
    View for joining a role.
    """

    model = Membership
    form_class = MembershipCreateForm

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
            membership = Membership.objects.get(identity=user.identity, role=role, status="active")
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
        kwargs = super(RoleJoinView, self).get_form_kwargs()
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
        return super().form_valid(form)


class MembershipDetailView(LoginRequiredMixin, DetailView[Membership]):
    """
    View for membership details.
    """

    model = Membership

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


class MembershipListView(LoginRequiredMixin, ListView[Membership]):
    """
    View for membership list.
    """

    model = Membership

    def get_queryset(self) -> QuerySet[Membership]:
        """
        Limit membership list to approvers, inviters and owners.

        Include only last 30 days if filter URI parameter with value expiring is used.
        """
        user = self.request.user
        if not user.is_authenticated:
            raise PermissionDenied
        groups = user.groups.all()
        queryset = Membership.objects.all()
        if not user.is_superuser:
            queryset = queryset.filter(
                Q(role__approvers__in=groups) | Q(role__inviters__in=groups) | Q(role__owner=user)
            ).distinct()
        if "filter" in self.request.GET:
            if self.request.GET["filter"] == "expiring":
                queryset = queryset.filter(
                    expire_date__gte=timezone.now().date(),
                    expire_date__lte=timezone.now().date() + datetime.timedelta(days=30),
                ).order_by("expire_date")
        return queryset.prefetch_related("identity", "role")


class RoleDetailView(LoginRequiredMixin, DetailView[Role]):
    """
    View for role details.
    """

    model = Role

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """
        Add memberships to context, if user is owner, approver or inviter.
        """
        context = super(RoleDetailView, self).get_context_data(**kwargs)
        user = self.request.user
        if not user.is_authenticated:
            raise PermissionDenied
        if self.object.is_inviter(user):
            context["memberships"] = Membership.objects.filter(
                role=self.object, expire_date__gte=timezone.now().date()
            ).prefetch_related("identity")
            context["is_inviter"] = True
        if self.object.is_approver(user):
            context["is_approver"] = True
        return context


class RoleInviteIdentitySearch(IdentitySearchView):
    """
    Subclass of IdentitySearchView for adding identities to role.
    """

    template_name = "role/role_invite_identity.html"

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """
        Add form and role to the context data.
        Add searched email and information if it has been found.
        """
        context = super(RoleInviteIdentitySearch, self).get_context_data(**kwargs)
        email = self.request.GET.get("email")
        context["email_found"] = (
            Identity.objects.filter(email_addresses__address__iexact=email).exists() if email else ""
        )
        self.request.session["invitation_email_address"] = email
        context["role"] = get_object_or_404(Role, pk=self.kwargs.get("role_pk"))
        return context


class BaseRoleInviteView(LoginRequiredMixin, CreateView[Membership, MembershipCreateForm | MembershipEmailCreateForm]):
    """
    Base view for inviting a user to a role.
    """

    model = Membership
    template_name = "role/role_invite.html"

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
        context = super(BaseRoleInviteView, self).get_context_data(**kwargs)
        context["role"] = get_object_or_404(Role, pk=self.kwargs.get("role_pk"))
        return context

    def get_form_kwargs(self) -> dict[str, Any]:
        """
        Add role to form kwargs.
        """
        kwargs = super(BaseRoleInviteView, self).get_form_kwargs()
        kwargs["role"] = get_object_or_404(Role, pk=self.kwargs.get("role_pk"))
        return kwargs


class RoleInviteView(BaseRoleInviteView):
    """
    Invite view for identities found in the registry.
    """

    form_class = MembershipCreateForm

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """
        Add identity to context.
        """
        context = super(RoleInviteView, self).get_context_data(**kwargs)
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
        return super().form_valid(form)


class RoleInviteLdapView(BaseRoleInviteView):
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
        context = super(RoleInviteLdapView, self).get_context_data(**kwargs)
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
            given_names_verification=2,
            surname=user["sn"],
            surname_verification=2,
        )
        if "mail" in user:
            EmailAddress.objects.create(address=user["mail"], identity=identity)
        if "schacDateOfBirth" in user:
            identity.date_of_birth = datetime.datetime.strptime(user["schacDateOfBirth"], "%Y%m%d").date()
            identity.date_of_birth_verification = 2
        if "preferredLanguage" in user and user["preferredLanguage"] in [k for k, v in settings.LANGUAGES]:
            identity.preferred_language = user["preferredLanguage"]
        fpic = self._parse_fpic(user)
        if fpic:
            identity.fpic = fpic
            identity.fpic_verification = 2
        identity.save()
        Identifier.objects.get_or_create(
            type="eppn",
            value=f"{user['uid']}{settings.LOCAL_EPPN_SUFFIX}",
            identity=identity,
            deactivated_at=None,
        )
        if fpic:
            Identifier.objects.get_or_create(type="fpic", value=fpic, identity=identity, deactivated_at=None)
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
                type="eppn",
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
                    type="fpic",
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
        return super().form_valid(form)


class RoleInviteEmailView(BaseRoleInviteView):
    """
    View for inviting a user to a role with an email-address.
    """

    form_class = MembershipEmailCreateForm

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """
        Add email to context.
        """
        context = super(RoleInviteEmailView, self).get_context_data(**kwargs)
        context["email"] = self.request.session.get("invitation_email_address")
        if not context["email"]:
            raise PermissionDenied
        return context

    def get_form_kwargs(self) -> dict[str, Any]:
        """
        Add email to form kwargs.
        """
        kwargs = super(RoleInviteEmailView, self).get_form_kwargs()
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
        form.instance.inviter = user
        if form.instance.role.is_approver(user=user):
            form.instance.approver = user
        if hasattr(form, "cleaned_data") and "invite_language" in form.cleaned_data:
            invite_language = form.cleaned_data["invite_language"]
        else:
            invite_language = "en"
        membership = form.save()
        token = Token.objects.create_invite_token(membership=membership)
        send_invite_email(membership, token, invite_email_address, lang=invite_language, request=self.request)
        messages.add_message(self.request, messages.INFO, _("Invite email sent."))
        return redirect("membership-detail", pk=membership.pk)


class RoleListApproverView(LoginRequiredMixin, ListView[Role]):
    """
    List all roles where user is an approver.
    """

    model = Role
    template_name = "role/role_list_approver.html"

    def get_queryset(self) -> QuerySet[Role]:
        """
        Filter queryset to approvers and owners.
        """
        user = self.request.user
        if not user.is_authenticated:
            raise PermissionDenied
        groups = user.groups.all()
        queryset = Role.objects.filter(Q(approvers__in=groups) | Q(owner=user)).distinct()
        return queryset.prefetch_related("owner", "parent")


class RoleListInviterView(LoginRequiredMixin, ListView[Role]):
    """
    List all roles where user is an inviter.
    """

    model = Role
    template_name = "role/role_list_inviter.html"

    def get_queryset(self) -> QuerySet[Role]:
        """
        Filter queryset to inviters, approvers and owners.
        """
        user = self.request.user
        if not user.is_authenticated:
            raise PermissionDenied
        groups = user.groups.all()
        queryset = Role.objects.filter(Q(approvers__in=groups) | Q(inviters__in=groups) | Q(owner=user)).distinct()
        return queryset.prefetch_related("owner", "parent")


class RoleListOwnerView(LoginRequiredMixin, ListView[Role]):
    """
    List all roles owned by the user.
    """

    model = Role
    template_name = "role/role_list_owner.html"

    def get_queryset(self) -> QuerySet[Role]:
        """
        Filter queryset to owners.
        """
        user = self.request.user
        if not user.is_authenticated:
            raise PermissionDenied
        queryset = Role.objects.filter(owner=user)
        return queryset.prefetch_related("owner", "parent")


class MembershipClaimView(LoginRequiredMixin, View):
    """
    Claim an invitation to a role membership.
    """

    def get(self, request: HttpRequest) -> HttpResponse:
        user = self.request.user
        if not user.is_authenticated:
            raise PermissionDenied
        if not hasattr(user, "identity"):
            Identity.objects.create(user=user, given_names=user.first_name, surname=user.last_name)
        membership_pk = claim_membership(request, user.identity)
        if membership_pk == -1:
            return redirect("front-page")
        return redirect("membership-detail", pk=membership_pk)


class RoleSearchView(LoginRequiredMixin, ListView[Role]):
    """
    View for role search.
    """

    template_name = "role/role_search.html"
    model = Role

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponseBase:
        if not self.request.user.has_perm("role.search_roles"):
            raise PermissionDenied
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """
        Add search form to ListView, including search parameters if present.
        """
        context = super(RoleSearchView, self).get_context_data(**kwargs)
        if "search" in self.request.GET:
            context["form"] = TextSearchForm(self.request.GET)
        else:
            context["form"] = TextSearchForm()
        return context

    def get_queryset(self) -> QuerySet[Role]:
        """
        Filter queryset based on search parameters.
        """
        queryset = Role.objects.all()
        if "search" not in self.request.GET:
            return queryset.none()
        search = self.request.GET["search"]
        if get_language() == "fi":
            queryset = queryset.filter(Q(identifier__icontains=search) | Q(name_fi__icontains=search))
        elif get_language() == "sv":
            queryset = queryset.filter(Q(identifier__icontains=search) | Q(name_sv__icontains=search))
        else:
            queryset = queryset.filter(Q(identifier__icontains=search) | Q(name_en__icontains=search))
        return queryset.prefetch_related("owner", "parent")
