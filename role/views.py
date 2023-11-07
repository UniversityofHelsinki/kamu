import datetime

from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.messages.views import SuccessMessageMixin
from django.db.models import Q
from django.http import Http404
from django.shortcuts import get_object_or_404, redirect
from django.utils import timezone
from django.utils.translation import get_language
from django.utils.translation import gettext as _
from django.views.generic import DetailView, ListView
from django.views.generic.edit import CreateView

from identity.models import Identity
from role.forms import MembershipCreateForm, RoleCreateForm, TextSearchForm
from role.models import Membership, Role


class RoleJoinView(LoginRequiredMixin, CreateView[Membership, MembershipCreateForm]):
    model = Membership
    form_class = MembershipCreateForm

    def get(self, request, *args, **kwargs):
        """
        Returns user to role details if they don't have an identity
        """
        user = self.request.user if self.request.user.is_authenticated else None
        if not Identity.objects.filter(user=user).exists():
            messages.add_message(request, messages.WARNING, _("You need to create an identity first."))
            return redirect("role-detail", pk=kwargs.pop("role_pk"))
        return super().get(request, *args, **kwargs)

    def get_initial(self):
        """
        Adds initial values to start_date and expire_date
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
        Add Role maximum_duration to form kwargs
        """

        kwargs = super(RoleJoinView, self).get_form_kwargs()
        kwargs["maximum_duration"] = get_object_or_404(Role, pk=self.kwargs.get("role_pk")).maximum_duration
        return kwargs

    def form_valid(self, form):
        form.instance.identity = self.request.user.identity if self.request.user.is_authenticated else None
        if not form.instance.identity:
            raise Http404(_("Missing form identity."))
        form.instance.role = get_object_or_404(Role, pk=self.kwargs.get("role_pk"))
        return super().form_valid(form)


class MembershipDetailView(LoginRequiredMixin, DetailView[Membership]):
    model = Membership


class MembershipListView(LoginRequiredMixin, ListView[Membership]):
    model = Membership

    def get_queryset(self):
        user = self.request.user
        if not user.is_authenticated:
            raise Http404(_("User not authenticated"))
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
        return queryset.prefetch_related("identity__attributes", "role")


class RoleCreateView(LoginRequiredMixin, SuccessMessageMixin, CreateView[Role, RoleCreateForm]):
    model = Role
    form_class = RoleCreateForm
    success_message = _("New role created.")


class RoleDetailView(LoginRequiredMixin, DetailView[Role]):
    model = Role

    def get_context_data(self, **kwargs):
        context = super(RoleDetailView, self).get_context_data(**kwargs)
        context["memberships"] = Membership.objects.filter(
            role=self.object, expire_date__gte=timezone.now().date()
        ).prefetch_related("identity__attributes")
        return context


class RoleListView(LoginRequiredMixin, ListView[Role]):
    model = Role

    def get_queryset(self):
        user = self.request.user
        if not user.is_authenticated:
            raise Http404(_("User not authenticated"))
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
    template_name = "role/role_search.html"
    model = Role

    def get_context_data(self, **kwargs):
        context = super(RoleSearchView, self).get_context_data(**kwargs)
        if "search" in self.request.GET:
            context["form"] = TextSearchForm(self.request.GET)
        else:
            context["form"] = TextSearchForm()
        return context

    def get_queryset(self):
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
