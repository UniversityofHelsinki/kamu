"""
Identity app views for the UI.
"""

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
    """
    View for the identity details.
    """

    model = Identity

    def get_context_data(self, **kwargs):
        context = super(IdentityDetailView, self).get_context_data(**kwargs)
        context["memberships"] = Membership.objects.filter(
            identity=self.object, expire_date__gte=timezone.now().date()
        ).prefetch_related("identity__email_addresses")
        return context


class IdentityMeView(LoginRequiredMixin, View):
    """
    Redirect to current user's detail view.
    """

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
    """
    Identity search view with results list.
    """

    template_name = "identity/identity_search.html"
    model = Identity

    def get_context_data(self, **kwargs):
        """
        Add form to the ListView.
        """
        context = super(IdentitySearchView, self).get_context_data(**kwargs)
        context["form"] = IdentitySearchForm(self.request.GET)
        return context

    def get_queryset(self):
        """
        Filter results based on URL parameters.
        """
        queryset = Identity.objects.all()
        given_names = self.request.GET.get("given_names")
        surname = self.request.GET.get("surname")
        email = self.request.GET.get("email")
        if not given_names and not surname and not email:
            return queryset.none()
        if given_names:
            queryset = queryset.filter(given_names__icontains=given_names)
        if surname:
            queryset = queryset.filter(surname__icontains=surname)
        if email:
            queryset = queryset.filter(email_addresses__address__icontains=email)
        return queryset
