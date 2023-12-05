"""
Role app views for the UI.
"""

import datetime

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

from identity.models import Identity
from role.forms import MembershipCreateForm, TextSearchForm
from role.models import Membership, Role


class RoleJoinView(LoginRequiredMixin, CreateView[Membership, MembershipCreateForm]):
    """
    View for joining a role.
    """

    model = Membership
    form_class = MembershipCreateForm

    def get(self, request, *args, **kwargs):
        """
        Returns user to role details if they don't have an identity.
        """
        user = self.request.user if self.request.user.is_authenticated else None
        if not Identity.objects.filter(user=user).exists():
            messages.add_message(request, messages.WARNING, _("You need to create an identity first."))
            return redirect("role-detail", pk=kwargs.pop("role_pk"))
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
        Set identity and role for the membership.
        """
        form.instance.identity = self.request.user.identity if self.request.user.is_authenticated else None
        if not form.instance.identity:
            raise PermissionDenied
        form.instance.role = get_object_or_404(Role, pk=self.kwargs.get("role_pk"))
        return super().form_valid(form)


class MembershipDetailView(LoginRequiredMixin, DetailView[Membership]):
    """
    View for membership details.
    """

    model = Membership


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
        if (
            user.is_superuser
            or self.object.owner == user
            or user.groups.filter(
                Q(id__in=self.object.approvers.all()) | Q(id__in=self.object.inviters.all())
            ).exists()
        ):
            context["memberships"] = Membership.objects.filter(
                role=self.object, expire_date__gte=timezone.now().date()
            ).prefetch_related("identity")
        return context


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
