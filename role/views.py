"""
Role app views for the UI.
"""

import datetime
from typing import Any

from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import PermissionDenied
from django.db.models import Q
from django.shortcuts import get_object_or_404, redirect
from django.utils import timezone
from django.utils.translation import get_language
from django.utils.translation import gettext as _
from django.views.generic import DetailView, ListView
from django.views.generic.edit import CreateView

from base.connectors.email import send_invite_email
from base.models import Token
from identity.models import Identity
from identity.views import IdentitySearchView
from role.forms import MembershipCreateForm, MembershipEmailCreateForm, TextSearchForm
from role.models import Membership, Role


class RoleJoinView(LoginRequiredMixin, CreateView[Membership, MembershipCreateForm]):
    """
    View for joining a role.
    """

    model = Membership
    form_class = MembershipCreateForm

    def get(self, request, *args, **kwargs):
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

    def get_initial(self):
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

    def get_form_kwargs(self):
        """
        Add role to form kwargs.
        """
        kwargs = super(RoleJoinView, self).get_form_kwargs()
        kwargs["role"] = get_object_or_404(Role, pk=self.kwargs.get("role_pk"))
        return kwargs

    def form_valid(self, form):
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

    def get_queryset(self):
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

    def get_queryset(self):
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

    def get_context_data(self, **kwargs):
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

    def get_context_data(self, **kwargs):
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

    def get_initial(self):
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

    def get_context_data(self, **kwargs) -> dict[str, Any]:
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

    def get_context_data(self, **kwargs):
        """
        Add identity to context.
        """
        context = super(RoleInviteView, self).get_context_data(**kwargs)
        context["identity"] = get_object_or_404(Identity, pk=self.kwargs.get("identity_pk"))
        return context

    def form_valid(self, form):
        """
        Set role and other data to the membership.
        """
        form.instance.identity = get_object_or_404(Identity, pk=self.kwargs.get("identity_pk"))
        form.instance.role = get_object_or_404(Role, pk=self.kwargs.get("role_pk"))
        form.instance.inviter = self.request.user
        return super().form_valid(form)


class RoleInviteEmailView(BaseRoleInviteView):
    """
    View for inviting a user to a role with an email-address.
    """

    form_class = MembershipEmailCreateForm

    def get_context_data(self, **kwargs):
        """
        Add email to context.
        """
        context = super(RoleInviteEmailView, self).get_context_data(**kwargs)
        context["email"] = self.request.session.get("invitation_email_address")
        if not context["email"]:
            raise PermissionDenied
        return context

    def get_form_kwargs(self):
        """
        Add email to form kwargs.
        """
        kwargs = super(RoleInviteEmailView, self).get_form_kwargs()
        kwargs["email"] = self.request.session.get("invitation_email_address")
        return kwargs

    def form_valid(self, form):
        """
        Set role and other data to the membership.
        """
        form.instance.identity = None
        form.instance.role = get_object_or_404(Role, pk=self.kwargs.get("role_pk"))
        form.instance.inviter = self.request.user
        if hasattr(form, "cleaned_data") and "invite_language" in form.cleaned_data:
            invite_language = form.cleaned_data["invite_language"]
        else:
            invite_language = "en"
        membership = form.save()
        token = Token.objects.create_invite_token(membership=membership)
        send_invite_email(membership, token, membership.invite_email_address, lang=invite_language)
        messages.add_message(self.request, messages.INFO, _("Invite email sent."))
        return redirect("membership-detail", pk=membership.pk)


class RoleListView(LoginRequiredMixin, ListView[Role]):
    """
    View for role list.
    """

    model = Role

    def get_queryset(self):
        """
        Filter queryset to inviters, approvers or owners, based on filter URL parameter.
        """
        user = self.request.user
        if not user.is_authenticated:
            raise PermissionDenied
        groups = user.groups.all()
        queryset = Role.objects.all()
        if "filter" in self.request.GET:
            if self.request.GET["filter"] == "inviter":
                queryset = queryset.filter(inviters__in=groups)
            elif self.request.GET["filter"] == "approver":
                queryset = queryset.filter(approvers__in=groups)
            if self.request.GET["filter"] == "owner":
                queryset = queryset.filter(owner=user)
        return queryset.prefetch_related("owner", "parent")


class RoleSearchView(LoginRequiredMixin, ListView[Role]):
    """
    View for role search.
    """

    template_name = "role/role_search.html"
    model = Role

    def get_context_data(self, **kwargs):
        """
        Add search form to ListView, including search parameters if present.
        """
        context = super(RoleSearchView, self).get_context_data(**kwargs)
        if "search" in self.request.GET:
            context["form"] = TextSearchForm(self.request.GET)
        else:
            context["form"] = TextSearchForm()
        return context

    def get_queryset(self):
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
