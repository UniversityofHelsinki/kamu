"""
Role views for the UI.
"""

from typing import Any

from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import PermissionDenied
from django.db.models import Q, QuerySet
from django.http import HttpRequest, HttpResponseBase
from django.utils import timezone
from django.utils.translation import get_language
from django.views.generic import DetailView, ListView

from kamu.forms.generic import TextSearchForm
from kamu.models.membership import Membership
from kamu.models.role import Role
from kamu.utils.audit import AuditLog

audit_log = AuditLog()


class RoleDetailView(LoginRequiredMixin, DetailView[Role]):
    """
    View for role details.
    """

    model = Role
    template_name = "role/role_detail.html"

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """
        Add memberships to context, if user is owner, approver or inviter.
        """
        context = super().get_context_data(**kwargs)
        user = self.request.user
        if not user.is_authenticated:
            raise PermissionDenied
        if self.object.is_inviter(user):
            context["memberships"] = Membership.objects.filter(
                role=self.object, expire_date__gte=timezone.now().date()
            ).prefetch_related("identity")
            audit_log.info(
                "List role memberships",
                category="role",
                action="read",
                outcome="success",
                request=self.request,
                objects=[self.object],
            )
            context["is_inviter"] = True
        if self.object.is_approver(user):
            context["is_approver"] = True
        return context


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


class RoleSearchView(LoginRequiredMixin, ListView[Role]):
    """
    View for role search.
    """

    model = Role
    template_name = "role/role_search.html"

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponseBase:
        if not self.request.user.has_perm("kamu.search_roles"):
            raise PermissionDenied
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """
        Add search form to ListView, including search parameters if present.
        """
        context = super().get_context_data(**kwargs)
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
            queryset = queryset.filter(
                Q(identifier__icontains=search) | Q(name_fi__icontains=search) | Q(description_fi__icontains=search)
            )
        elif get_language() == "sv":
            queryset = queryset.filter(
                Q(identifier__icontains=search) | Q(name_sv__icontains=search) | Q(description_sv__icontains=search)
            )
        else:
            queryset = queryset.filter(
                Q(identifier__icontains=search) | Q(name_en__icontains=search) | Q(description_en__icontains=search)
            )
        return queryset.prefetch_related("owner", "parent")
