from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import PermissionDenied
from django.shortcuts import redirect
from django.utils import timezone
from django.utils.translation import gettext as _
from django.views import View
from django.views.generic import DetailView, ListView

from identity.forms import IdentitySearchForm
from identity.models import Identity
from role.models import Membership


class IdentityDetailView(LoginRequiredMixin, DetailView):
    model = Identity

    def get_context_data(self, **kwargs):
        context = super(IdentityDetailView, self).get_context_data(**kwargs)
        context["attributes"] = self.object.get_attributes()
        context["memberships"] = Membership.objects.filter(
            identity=self.object, expire_date__gte=timezone.now().date()
        ).prefetch_related("identity__attributes")
        return context


class IdentityMeView(LoginRequiredMixin, View):
    def get(self, request):
        """
        Redirects user to their own identity detail page.
        Creates an identity for user if identity does not exist.
        """
        user = self.request.user if self.request.user.is_authenticated else None
        if not user:
            raise PermissionDenied
        try:
            identity = Identity.objects.get(user=user)
        except Identity.DoesNotExist:
            identity = Identity.objects.create(user=user)
            messages.add_message(request, messages.WARNING, _("New identity created."))
        return redirect("identity-detail", pk=identity.pk)


class IdentitySearchView(LoginRequiredMixin, ListView[Identity]):
    template_name = "identity/identity_search.html"
    model = Identity

    def get_context_data(self, **kwargs):
        context = super(IdentitySearchView, self).get_context_data(**kwargs)
        context["form"] = IdentitySearchForm(self.request.GET)
        return context

    def get_queryset(self):
        queryset = Identity.objects.all()
        first_name = self.request.GET.get("first_name")
        last_name = self.request.GET.get("last_name")
        email = self.request.GET.get("email")
        if not first_name and not last_name and not email:
            return queryset.none()
        if first_name:
            queryset = queryset.filter(
                attributes__attribute_type__identifier="first_name", attributes__value__icontains=first_name
            )
        if last_name:
            queryset = queryset.filter(
                attributes__attribute_type__identifier="last_name", attributes__value__icontains=last_name
            )
        if email:
            queryset = queryset.filter(
                attributes__attribute_type__identifier="email", attributes__value__icontains=email
            )
        return queryset
