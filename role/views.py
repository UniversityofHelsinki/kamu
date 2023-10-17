import datetime

from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import Http404
from django.shortcuts import get_object_or_404, redirect
from django.utils import timezone
from django.utils.translation import gettext as _
from django.views.generic import DetailView, ListView
from django.views.generic.edit import CreateView

from identity.models import Identity
from role.forms import MembershipCreateForm, RoleCreateForm
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
        role = get_object_or_404(Role, pk=self.kwargs.get("role_pk"))
        start_date = timezone.now().date()
        expire_date = timezone.now().date() + datetime.timedelta(days=role.maximum_duration)
        return {
            "start_date": start_date,
            "expire_date": expire_date,
        }

    def form_valid(self, form):
        form.instance.identity = self.request.user.identity if self.request.user.is_authenticated else None
        if not form.instance.identity:
            raise Http404(_("Missing form identity."))
        form.instance.role = get_object_or_404(Role, pk=self.kwargs.get("role_pk"))
        return super().form_valid(form)


class MembershipDetailView(LoginRequiredMixin, DetailView[Membership]):
    model = Membership


class RoleCreateView(LoginRequiredMixin, CreateView[Role, RoleCreateForm]):
    model = Role
    form_class = RoleCreateForm


class RoleDetailView(LoginRequiredMixin, DetailView[Role]):
    model = Role


class RoleListView(LoginRequiredMixin, ListView[Role]):
    model = Role
