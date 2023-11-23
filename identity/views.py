"""
Identity app views for the UI.
"""

from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.models import Group
from django.core.exceptions import PermissionDenied
from django.db.models import Q
from django.shortcuts import redirect
from django.urls import reverse
from django.utils import timezone
from django.utils.translation import gettext as _
from django.views import View
from django.views.generic import DetailView, ListView, UpdateView

from identity.forms import IdentityForm, IdentitySearchForm
from identity.models import Identity
from role.models import Membership


class IdentityDetailView(LoginRequiredMixin, DetailView):
    """
    View for the identity details.
    """

    model = Identity

    def get_context_data(self, **kwargs):
        """
        Add memberships to the context data.
        """
        context = super(IdentityDetailView, self).get_context_data(**kwargs)
        context["memberships"] = Membership.objects.filter(
            identity=self.object, expire_date__gte=timezone.now().date()
        )
        return context

    def get_queryset(self):
        """
        Restrict access to user's own information, unless
         - user has permission to view all basic information,
         - or user is an approver or inviter for the one of identity's groups.
        """
        queryset = super(IdentityDetailView, self).get_queryset()
        if not self.request.user.has_perms(["identity.view_basic_information"]):
            groups = self.request.user.groups.all() if self.request.user.groups else Group.objects.none()
            return queryset.filter(
                Q(user=self.request.user) | Q(roles__approvers__in=groups) | Q(roles__inviters__in=groups)
            ).distinct()
        return queryset


class IdentityUpdateView(UpdateView):
    model = Identity
    form_class = IdentityForm

    def form_valid(self, form):
        return super().form_valid(form)

    def get_form_kwargs(self):
        """
        Add request object to the form class.
        """
        kwargs = super(IdentityUpdateView, self).get_form_kwargs()
        kwargs["request"] = self.request
        return kwargs

    def get_queryset(self):
        """
        Restrict update to user's own information, unless user has permission to modify all basic information.
        """
        queryset = super(IdentityUpdateView, self).get_queryset()
        if not self.request.user.has_perms(["identity.change_basic_information"]):
            return queryset.filter(user=self.request.user)
        return queryset

    def get_success_url(self):
        pk = self.object.pk if self.object else None
        return reverse("identity-detail", kwargs={"pk": pk})


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
