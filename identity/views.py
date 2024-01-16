"""
Identity app views for the UI.
"""
from typing import Any
from urllib.parse import quote_plus

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.models import Group
from django.core.exceptions import PermissionDenied
from django.core.mail import send_mail
from django.db.models import Q, QuerySet
from django.forms import BaseForm
from django.http import (
    HttpRequest,
    HttpResponse,
    HttpResponseBase,
    HttpResponseRedirect,
)
from django.shortcuts import redirect
from django.urls import reverse
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.utils.translation import gettext as _
from django.views import View
from django.views.decorators.csrf import csrf_protect
from django.views.generic import (
    DetailView,
    FormView,
    ListView,
    TemplateView,
    UpdateView,
)
from ldap import SIZELIMIT_EXCEEDED
from ldap.filter import escape_filter_chars

from base.connectors.ldap import ldap_search
from base.connectors.sms import SmsConnector
from base.models import TimeLimitError, Token
from identity.forms import (
    ContactForm,
    EmailAddressVerificationForm,
    IdentityForm,
    IdentitySearchForm,
    PhoneNumberVerificationForm,
)
from identity.models import EmailAddress, Identifier, Identity, PhoneNumber
from role.models import Membership


class IdentityDetailView(LoginRequiredMixin, DetailView):
    """
    View for the identity details.
    """

    model = Identity

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """
        Add memberships to the context data.
        """
        context = super(IdentityDetailView, self).get_context_data(**kwargs)
        context["memberships"] = Membership.objects.filter(
            identity=self.object, expire_date__gte=timezone.now().date()
        )
        context["identifiers"] = Identifier.objects.filter(identity=self.object, deactivated_at=None)
        return context

    def get_queryset(self) -> QuerySet[Identity]:
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

    def form_valid(self, form: IdentityForm) -> HttpResponse:
        return super().form_valid(form)

    def get_form_kwargs(self) -> dict[str, Any]:
        """
        Add request object to the form class.
        """
        kwargs = super(IdentityUpdateView, self).get_form_kwargs()
        kwargs["request"] = self.request
        return kwargs

    def get_queryset(self) -> QuerySet[Identity]:
        """
        Restrict update to user's own information, unless user has permission to modify all basic information.
        """
        queryset = super(IdentityUpdateView, self).get_queryset()
        if not self.request.user.has_perms(["identity.change_basic_information"]):
            return queryset.filter(user=self.request.user)
        return queryset

    def get_success_url(self) -> str:
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

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """
        Check for resend button.
        """
        if "resend_code" in self.request.POST:
            self.object = self.get_object()
            self._create_verification_token()
            return redirect(self.post_redirect, pk=self.object.pk)
        return super().post(request, *args, **kwargs)

    def get_queryset(self) -> QuerySet[EmailAddress | PhoneNumber]:
        """
        Restrict update to user's own contacts.
        """
        if self.request.user.is_anonymous:
            return self.model.objects.none()
        return self.model.objects.filter(identity__user=self.request.user)

    def get_success_url(self) -> str:
        return reverse("contact-change", kwargs={"pk": self.object.identity.pk})

    def form_valid(self, form: BaseForm) -> HttpResponse:
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
            token = Token.objects.create_email_object_verification_token(self.object)
        except TimeLimitError:
            messages.add_message(self.request, messages.WARNING, _("Tried to send a new code too soon."))
            return False
        subject = _("Kamu service email address verification")
        message = _("Your verification code is: %(token)s") % {"token": token}
        from_email = getattr(settings, "TOKEN_FROM_EMAIL", None)
        send_mail(subject, message, from_email, [self.object.address])
        messages.add_message(self.request, messages.INFO, _("Verification code sent."))
        return True

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """
        Create and send a code when loading a page.
        """
        get = super().get(request, *args, **kwargs)
        if not Token.objects.filter(email_object=self.object).exists():
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
            token = Token.objects.create_phone_object_verification_token(self.object)
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

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """
        Create and send a code when loading a page.
        """
        get = super().get(request, *args, **kwargs)
        if not Token.objects.filter(phone_object=self.object).exists():
            self._create_verification_token()
        return get


class ContactView(LoginRequiredMixin, FormView):
    """
    List contact addresses and add new contact addresses.
    """

    form_class = ContactForm
    template_name = "contact_address.html"
    success_url = "#"

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponseBase:
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

    def get_form_kwargs(self) -> dict[str, Any]:
        """
        Add identity object to the form class.
        """
        kwargs = super(ContactView, self).get_form_kwargs()
        kwargs["identity"] = self.identity
        return kwargs

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """
        Add lists of users email_addresses and phone_numbers to context.
        """
        context = super(ContactView, self).get_context_data(**kwargs)
        identity = Identity.objects.get(pk=self.kwargs.get("pk"))
        context["email_list"] = identity.email_addresses.all().order_by("priority")
        context["phone_list"] = identity.phone_numbers.all().order_by("priority")
        return context

    def form_valid(self, form: ContactForm) -> HttpResponse:
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

    def _change_contact_priority(self, model: type[EmailAddress] | type[PhoneNumber], pk: int, direction: str) -> None:
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

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
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


class IdentifierView(LoginRequiredMixin, TemplateView):
    """
    List and deactivate identifiers.
    """

    template_name = "identifier.html"

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponseBase:
        """
        Check that user has view permissions to identifiers. Change permissions in case of
        POST message.
        """
        user = self.request.user if self.request.user.is_authenticated else None
        if not user:
            raise PermissionDenied
        try:
            self.identity = Identity.objects.get(pk=self.kwargs.get("pk"))
        except Identity.DoesNotExist:
            raise PermissionDenied
        if self.identity.user != user and not user.has_perms(["identity.view_identifiers"]):
            raise PermissionDenied
        if (
            request.method
            and request.method.lower() == "post"
            and self.identity.user != user
            and not user.has_perms(["identity.change_identifiers"])
        ):
            raise PermissionDenied
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """
        Add lists of users email_addresses and phone_numbers to context.
        """
        context = super(IdentifierView, self).get_context_data(**kwargs)
        identity = Identity.objects.get(pk=self.kwargs.get("pk"))
        context["identifier_active_list"] = Identifier.objects.filter(identity=identity, deactivated_at=None)
        context["identifier_deactivated_list"] = Identifier.objects.filter(
            identity=identity, deactivated_at__isnull=False
        )
        context["identity"] = identity
        return context

    @staticmethod
    def _get_linking_view(backend: str) -> str | None:
        linking = {
            "hy": "login-shibboleth",
            "haka": "login-haka",
            "edugain": "login-edugain",
            "suomifi": "login-suomifi",
            "google": "login-google",
            "microsoft": "login-microsoft",
        }
        return linking.get(backend)

    def _get_linking_url(self, linking_view: str) -> str:
        """
        Get url for linking identifier.

        If linking view is in OIDC_VIEWS and OIDC_LOGOUT_PATH is given, redirect user
        to logout url, with a redirect to linking url.

        If SERVICE_LINK_URL is given, use it in redirection. This may be needed for
        external logout.
        """
        linking_url = (
            reverse(linking_view) + "?next=" + reverse("identity-identifier", kwargs={"pk": self.identity.pk})
        )
        oidc_views = getattr(settings, "OIDC_VIEWS", [])
        oidc_logout_path = getattr(settings, "OIDC_LOGOUT_PATH", None)
        service_link_url = getattr(settings, "SERVICE_LINK_URL", None)
        if linking_view in oidc_views and oidc_logout_path:
            if service_link_url:
                logout_url = f"{ oidc_logout_path }{ quote_plus(service_link_url)}{ quote_plus(linking_url) }"
            else:
                logout_url = f"{ oidc_logout_path }{ quote_plus(linking_url) }"
            return logout_url
        return linking_url

    @method_decorator(csrf_protect)
    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """
        Check for identifier deactivation. Prevent deactivation of last active identifier,
        if user does not have generic change_indentifier permission.

        If linking identifier, set session parameters and redirect to correct linking view.
        """
        data = self.request.POST
        if "identifier_deactivate" in data:
            pk = int(data["identifier_deactivate"])
            if not self.request.user.has_perms(["identity.change_identifiers"]) and (
                not Identifier.objects.filter(identity=self.identity, deactivated_at__isnull=True)
                .exclude(pk=pk)
                .exists()
            ):
                messages.add_message(self.request, messages.WARNING, _("Cannot deactivate last active identifier."))
            else:
                try:
                    identifier = Identifier.objects.get(pk=pk, identity=self.identity, deactivated_at__isnull=True)
                    identifier.deactivated_at = timezone.now()
                    identifier.save()
                except Identifier.DoesNotExist:
                    pass
        elif "link_identifier" in data:
            identifier_type = str(data["link_identifier"])
            linking_view = self._get_linking_view(identifier_type)
            if linking_view:
                self.request.session["link_identifier"] = True
                self.request.session["link_identifier_time"] = timezone.now().isoformat()
                linking_url = self._get_linking_url(linking_view)
                return HttpResponseRedirect(linking_url)
        return redirect("identity-identifier", pk=self.identity.pk)


class IdentityMeView(LoginRequiredMixin, View):
    """
    Redirect to current user's detail view.
    """

    def get(self, request: HttpRequest) -> HttpResponse:
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
            identity = Identity.objects.create(
                user=user,
                given_names=user.first_name,
                given_names_verification=2,
                surname=user.last_name,
                surname_verification=2,
            )
            if user.email:
                EmailAddress.objects.create(address=user.email, identity=identity)
            messages.add_message(request, messages.WARNING, _("New identity created."))
        return redirect("identity-detail", pk=identity.pk)


class IdentitySearchView(LoginRequiredMixin, ListView[Identity]):
    """
    Identity search view with results list.
    """

    template_name = "identity/identity_search.html"
    model = Identity

    def _ldap_search_attribute(self, attribute: list[tuple[str, str, bool]]) -> list | None:
        """
        Search LDAP for attribute(s).

        attribute is the list of tuples containing LDAP attribute name, URL parameter name and wildcard boolean.

        Return empty list if no search parameters are found.
        Return None if LDAP search does not succeed.
        """
        ldap_parameters = []
        for attr in attribute:
            ldap_name, param_name, wildcard = attr
            value = self.request.GET.get(param_name)
            if not value:
                continue
            if wildcard:
                ldap_parameters.append("(" + ldap_name + "=*" + escape_filter_chars(value) + "*)")
            else:
                ldap_parameters.append("(" + ldap_name + "=" + escape_filter_chars(value) + ")")
        if not ldap_parameters:
            return []
        try:
            ldap_result = ldap_search("(&" + "".join(ldap_parameters) + ")")
        except SIZELIMIT_EXCEEDED:
            messages.add_message(
                self.request,
                messages.WARNING,
                _("LDAP search returned too many results, please refine your search parameters."),
            )
            return []
        return ldap_result if isinstance(ldap_result, list) else None

    def _get_ldap_results(self) -> list | None:
        """
        Search LDAP based on URL parameters.

        Append separate search results to combined results and return them.

        Return None if LDAP search does not succeed.
        """
        results: set = set()
        search_attributes = [
            [("givenName", "given_names", True), ("sn", "surname", True)],
            [("mail", "email", False)],
            [("uid", "uid", False)],
        ]
        for attribute in search_attributes:
            search_result = self._ldap_search_attribute(attribute)
            if search_result is None:
                return None
            else:
                results |= set(frozenset(res.items()) for res in search_result)
        return [dict(res) for res in results]

    @staticmethod
    def _filter_ldap_list(object_list: QuerySet[Identity], ldap_results: list) -> list:
        """
        Filter out LDAP results where uid is already in object_list and sort results.
        """
        result_uids = set(object_list.values_list("uid", flat=True))
        return sorted([res for res in ldap_results if res["uid"] not in result_uids], key=lambda x: x["cn"])

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """
        Add form and searched phone and email to context data.
        """
        context = super(IdentitySearchView, self).get_context_data(**kwargs)
        context["phone"] = self.request.GET.get("phone", "").replace(" ", "")
        context["email"] = self.request.GET.get("email")
        context["form"] = IdentitySearchForm(self.request.GET)
        ldap_results = self._get_ldap_results()
        if isinstance(ldap_results, list):
            context["ldap_results"] = self._filter_ldap_list(context["object_list"], ldap_results)
        else:
            messages.add_message(
                self.request, messages.ERROR, _("LDAP search failed, could not search existing accounts.")
            )
        return context

    def get_queryset(self) -> QuerySet[Identity]:
        """
        Filter results based on URL parameters.

        Return all results with the exact email address or phone number, regardless of names.
        """
        queryset = Identity.objects.all()
        given_names = self.request.GET.get("given_names")
        surname = self.request.GET.get("surname")
        email = self.request.GET.get("email")
        phone = self.request.GET.get("phone")
        uid = self.request.GET.get("uid")
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
        if uid:
            queryset = queryset.union(Identity.objects.filter(uid=uid))
        if phone:
            phone = phone.replace(" ", "")
            queryset = queryset.union(Identity.objects.filter(phone_numbers__number__exact=phone))
        return queryset
