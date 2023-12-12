"""
Identity app views for the UI.
"""
from typing import Any

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.models import Group
from django.core.exceptions import PermissionDenied
from django.core.mail import send_mail
from django.db.models import Q
from django.shortcuts import redirect
from django.urls import reverse
from django.utils import timezone
from django.utils.translation import gettext as _
from django.views import View
from django.views.generic import DetailView, FormView, ListView, UpdateView

from base.connectors.sms import SmsConnector
from base.models import TimeLimitError, Token
from identity.forms import (
    ContactForm,
    EmailAddressVerificationForm,
    IdentityForm,
    IdentitySearchForm,
    PhoneNumberVerificationForm,
)
from identity.models import EmailAddress, Identity, PhoneNumber
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


class BaseVerificationView(LoginRequiredMixin, UpdateView):
    """
    A base view for verifying contacts
    """

    post_redirect = ""

    def _create_verification_token(self) -> bool:
        """
        Create and send a verification token.
        """
        return False

    def post(self, request, *args, **kwargs):
        """
        Check for resend button.
        """
        if "resend_code" in self.request.POST:
            self.object = self.get_object()
            self._create_verification_token()
            return redirect(self.post_redirect, pk=self.object.pk)
        return super().post(request, *args, **kwargs)

    def get_queryset(self):
        """
        Restrict update to user's own contacts.
        """
        if self.request.user.is_anonymous:
            return self.model.objects.none()
        return self.model.objects.filter(identity__user=self.request.user)

    def get_success_url(self):
        return reverse("contact-change", kwargs={"pk": self.object.identity.pk})

    def form_valid(self, form):
        """
        Verify a contact if code was correct.
        """
        self.object.verified = True
        self.object.save()
        return super().form_valid(form)


class EmailAddressVerificationView(BaseVerificationView):
    """
    A view for verifying an email address
    """

    form_class = EmailAddressVerificationForm
    template_name = "verify_email_address.html"
    post_redirect = "email-verify"
    model = EmailAddress

    def _create_verification_token(self) -> bool:
        """
        Create and send a verification token.
        """
        try:
            token = Token.objects.create_email_verification_token(self.object)
        except TimeLimitError:
            messages.add_message(self.request, messages.WARNING, _("Tried to send a new code too soon."))
            return False
        subject = _("Kamu service email address verification")
        message = _("Your verification code is: %(token)s") % {"token": token}
        from_email = getattr(settings, "TOKEN_FROM_EMAIL", None)
        send_mail(subject, message, from_email, [self.object.address])
        messages.add_message(self.request, messages.INFO, _("Verification code sent."))
        return True

    def get(self, request, *args, **kwargs):
        """
        Create and send a code when loading a page.
        """
        get = super().get(request, *args, **kwargs)
        if not Token.objects.filter(email=self.object).exists():
            self._create_verification_token()
        return get


class PhoneNumberVerificationView(BaseVerificationView):
    """
    A view for verifying a phone number.
    """

    form_class = PhoneNumberVerificationForm
    template_name = "verify_phone_number.html"
    post_redirect = "phone-verify"
    model = PhoneNumber

    def _create_verification_token(self) -> bool:
        """
        Create and send a verification token.
        """
        try:
            token = Token.objects.create_sms_verification_token(self.object)
        except TimeLimitError:
            messages.add_message(self.request, messages.WARNING, _("Tried to send a new code too soon."))
            return False
        sms_connector = SmsConnector()

        success = sms_connector.send_sms(self.object.number, _("Kamu verification code: %(token)s") % {"token": token})
        if success:
            messages.add_message(self.request, messages.INFO, _("Verification code sent."))
            return True
        else:
            messages.add_message(self.request, messages.ERROR, _("Could not send an SMS message."))
            return False

    def get(self, request, *args, **kwargs):
        """
        Create and send a code when loading a page.
        """
        get = super().get(request, *args, **kwargs)
        if not Token.objects.filter(phone=self.object).exists():
            self._create_verification_token()
        return get


class ContactView(LoginRequiredMixin, FormView):
    """
    List contact addresses and add new contact addresses.
    """

    form_class = ContactForm
    template_name = "contact_address.html"
    success_url = "#"

    def dispatch(self, request, *args, **kwargs):
        user = self.request.user if self.request.user.is_authenticated else None
        if not user:
            raise PermissionDenied
        try:
            self.identity = Identity.objects.get(pk=self.kwargs.get("pk"))
        except Identity.DoesNotExist:
            raise PermissionDenied
        if self.identity.user != user and not user.has_perms(["identity.change_contacts"]):
            raise PermissionDenied
        return super().dispatch(request, *args, **kwargs)

    def get_form_kwargs(self):
        """
        Add identity object to the form class.
        """
        kwargs = super(ContactView, self).get_form_kwargs()
        kwargs["identity"] = self.identity
        return kwargs

    def get_context_data(self, **kwargs):
        """
        Add lists of users email_addresses and phone_numbers to context.
        """
        context = super(ContactView, self).get_context_data(**kwargs)
        identity = Identity.objects.get(pk=self.kwargs.get("pk"))
        context["email_list"] = identity.email_addresses.all().order_by("priority")
        context["phone_list"] = identity.phone_numbers.all().order_by("priority")
        return context

    def form_valid(self, form):
        """
        Create an email address or a phone number if form is valid.
        """
        if not hasattr(form, "cleaned_data"):
            return super().form_valid(form)
        if form.cleaned_data["contact_type"] == "email":
            last_email = EmailAddress.objects.filter(identity=form.identity).order_by("priority").last()
            priority = last_email.priority + 1 if last_email else 0
            EmailAddress.objects.create(
                identity=form.identity, address=form.cleaned_data["contact"], priority=priority
            )
        if form.cleaned_data["contact_type"] == "phone":
            last_phone = PhoneNumber.objects.filter(identity=form.identity).order_by("priority").last()
            priority = last_phone.priority + 1 if last_phone else 0
            PhoneNumber.objects.create(identity=form.identity, number=form.cleaned_data["contact"], priority=priority)
        return super().form_valid(form)

    def _change_contact_priority(self, model, pk: int, direction: str) -> None:
        """
        Change contact priority up or down and move possible other objects to another direction,
        if priorities are the same.
        """
        obj = model.objects.get(pk=pk, identity=self.identity)
        if direction == "up" and obj.priority > 0:
            obj.priority -= 1
            obj.save()
            other_objs = model.objects.filter(priority=obj.priority, identity=self.identity).exclude(pk=obj.pk)
            for other_obj in other_objs:
                other_obj.priority += 1
                other_obj.save()
        if direction == "down":
            obj.priority += 1
            obj.save()
            other_objs = model.objects.filter(priority=obj.priority, identity=self.identity).exclude(pk=obj.pk)
            for other_obj in other_objs:
                other_obj.priority -= 1
                other_obj.save()

    def post(self, request, *args, **kwargs):
        """
        Check for contact removal and priority changes before normal form handling.
        """
        data = self.request.POST
        if "phone_remove" in data:
            pk = int(data["phone_remove"])
            PhoneNumber.objects.filter(pk=pk, identity=self.identity).delete()
            return redirect("contact-change", pk=self.identity.pk)
        if "email_remove" in data:
            pk = int(data["email_remove"])
            EmailAddress.objects.filter(pk=pk, identity=self.identity).delete()
            return redirect("contact-change", pk=self.identity.pk)
        if "email_up" in data:
            pk = int(data["email_up"])
            self._change_contact_priority(EmailAddress, pk, "up")
            return redirect("contact-change", pk=self.identity.pk)
        if "email_down" in data:
            pk = int(data["email_down"])
            self._change_contact_priority(EmailAddress, pk, "down")
            return redirect("contact-change", pk=self.identity.pk)
        if "phone_up" in data:
            pk = int(data["phone_up"])
            self._change_contact_priority(PhoneNumber, pk, "up")
            return redirect("contact-change", pk=self.identity.pk)
        if "phone_down" in data:
            pk = int(data["phone_down"])
            self._change_contact_priority(PhoneNumber, pk, "down")
            return redirect("contact-change", pk=self.identity.pk)
        return super().post(request, *args, **kwargs)


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

    def get_context_data(self, **kwargs) -> dict[str, Any]:
        """
        Add form and searched phone and email to context data.
        """
        context = super(IdentitySearchView, self).get_context_data(**kwargs)
        context["phone"] = self.request.GET.get("phone", "").replace(" ", "")
        context["email"] = self.request.GET.get("email")
        context["form"] = IdentitySearchForm(self.request.GET)
        return context

    def get_queryset(self):
        """
        Filter results based on URL parameters.

        Return all results with the exact email address or phone number, regardless of names.
        """
        queryset = Identity.objects.all()
        given_names = self.request.GET.get("given_names")
        surname = self.request.GET.get("surname")
        email = self.request.GET.get("email")
        phone = self.request.GET.get("phone")
        if not given_names and not surname:
            queryset = queryset.none()
        if given_names:
            queryset = queryset.filter(
                Q(given_names__icontains=given_names) | Q(given_name_display__icontains=given_names)
            )
        if surname:
            queryset = queryset.filter(Q(surname__icontains=surname) | Q(surname_display__icontains=surname))
        if email:
            queryset = queryset.union(Identity.objects.filter(email_addresses__address__iexact=email))
        if phone:
            phone = phone.replace(" ", "")
            queryset = queryset.union(Identity.objects.filter(phone_numbers__number__exact=phone))
        return queryset
