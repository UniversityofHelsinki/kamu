"""
Identity views for the UI.
"""

import string
from datetime import datetime
from typing import Any
from urllib.parse import quote_plus

from django.conf import settings
from django.contrib import messages
from django.contrib.admin.utils import construct_change_message
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.models import Group
from django.core.exceptions import ObjectDoesNotExist, PermissionDenied, ValidationError
from django.core.mail import send_mail
from django.core.validators import validate_email
from django.db import IntegrityError
from django.db.models import OuterRef, Q, QuerySet, Subquery
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

from kamu.connectors import ApiError
from kamu.connectors.candour import CandourApiConnector
from kamu.connectors.email import send_primary_email_changed_notification
from kamu.connectors.ldap import LDAP_SIZELIMIT_EXCEEDED, ldap_search
from kamu.connectors.sms import SmsConnector
from kamu.forms.identity import (
    ContactForm,
    EmailAddressVerificationForm,
    IdentityCombineForm,
    IdentityForm,
    IdentitySearchForm,
    PhoneNumberVerificationForm,
)
from kamu.models.account import Account
from kamu.models.contract import Contract, ContractTemplate
from kamu.models.identity import EmailAddress, Identifier, Identity, PhoneNumber
from kamu.models.membership import Membership
from kamu.models.role import Permission
from kamu.models.token import TimeLimitError, Token
from kamu.utils.audit import AuditLog
from kamu.utils.identity import (
    add_account_messages,
    combine_identities,
    combine_identities_requirements,
    create_or_verify_email_address,
    create_or_verify_phone_number,
    update_identity_attributes,
)
from kamu.utils.membership import add_missing_requirement_messages
from kamu.validators.identity import validate_fpic, validate_phone_number
from settings.common import LdapSearchAttributeType

audit_log = AuditLog()


class IdentityDetailView(LoginRequiredMixin, DetailView):
    """
    View for the identity details.
    """

    model = Identity
    template_name = "identity/identity_detail.html"

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """
        Add memberships to the context data.
        """
        context = super().get_context_data(**kwargs)
        context["memberships"] = Membership.objects.filter(
            identity=self.object, expire_date__gte=timezone.now().date()
        ).order_by(*Membership.get_ordering_by_role_name())
        context["expired_memberships"] = Membership.objects.filter(
            identity=self.object, expire_date__lt=timezone.now().date()
        ).order_by(*Membership.get_ordering_by_role_name())
        context["identifiers"] = Identifier.objects.filter(identity=self.object, deactivated_at=None)
        context["assurance_verified_level"] = getattr(
            settings, "ASSURANCE_LEVEL_DISPLAY_AS_VERIFIED", Identity.AssuranceLevel.MEDIUM
        )
        context["attribute_verified_level"] = getattr(
            settings, "ATTRIBUTE_VERIFICATION_LEVEL_DISPLAY_AS_VERIFIED", Identity.VerificationMethod.PHOTO_ID
        )
        return context

    def get_queryset(self) -> QuerySet[Identity]:
        """
        Restrict access to user's own information, unless
         - user has permission to view all basic information,
         - or user is an approver or inviter for the one of identity's groups.
        """
        queryset = super().get_queryset()
        if not self.request.user.has_perms(["kamu.view_basic_information"]):
            groups = self.request.user.groups.all() if self.request.user.groups else Group.objects.none()
            return queryset.filter(
                Q(user=self.request.user) | Q(roles__approvers__in=groups) | Q(roles__inviters__in=groups)
            ).distinct()
        return queryset

    def get_activable_accounts(self) -> list[dict[str, str]]:
        """
        Return a list of account types that the user has permissions for but has not yet activated.
        """
        account_permissions = self.object.get_permissions(permission_type=Permission.Type.ACCOUNT).values_list(
            "identifier", flat=True
        )
        existing_accounts = self.object.useraccount.values_list("type", flat=True)
        creatable_accounts = []
        for account_type in set(account_permissions) - set(existing_accounts):
            if settings.ACCOUNT_ACTIONS.get(account_type):
                creatable_accounts.append(
                    {
                        "type": account_type,
                        "name": Account.Type(account_type).label,
                        "action": settings.ACCOUNT_ACTIONS.get(account_type),
                    }
                )
        return creatable_accounts

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """
        Log viewing identity information.

        Add permissions used to view information as an extra log parameter.
        """
        get = super().get(request, *args, **kwargs)
        permissions = set(self.request.user.get_all_permissions()).intersection(
            {
                "identity.view_basic_information",
                "identity.view_restricted_information",
                "identity.view_contacts",
                "identity.view_contracts",
                "identity.view_identifiers",
            }
        )
        audit_log.info(
            "Read identity information",
            category="identity",
            action="read",
            outcome="success",
            request=self.request,
            objects=[self.object],
            extra={"permissions": str(permissions)},
        )
        missing_requirements = self.object.get_missing_requirements()
        if missing_requirements:
            add_missing_requirement_messages(self.request, missing_requirements, self.object)
        activable_accounts = self.get_activable_accounts()
        if activable_accounts:
            add_account_messages(self.request, activable_accounts, self.object)
        return get

    @method_decorator(csrf_protect)
    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """
        Check for combine identity posts.
        """
        self.object = self.get_object()
        if (
            "combine_target" in self.request.POST or "combine_source" in self.request.POST
        ) and self.request.user.has_perms(["kamu.combine_identities"]):
            if "combine_target" in self.request.POST:
                self.request.session["combine_identity_target"] = self.object.pk
                if "combine_identity_source" not in self.request.session:
                    messages.add_message(
                        self.request, messages.INFO, _("Selected as the target identity for identity combining.")
                    )
            if "combine_source" in self.request.POST:
                self.request.session["combine_identity_source"] = self.object.pk
                if "combine_identity_target" not in self.request.session:
                    messages.add_message(
                        self.request, messages.INFO, _("Selected as the source identity for identity combining.")
                    )
            if (
                "combine_identity_target" in self.request.session
                and "combine_identity_source" in self.request.session
                and self.request.session["combine_identity_target"] != self.request.session["combine_identity_source"]
            ):
                target = self.request.session["combine_identity_target"]
                source = self.request.session["combine_identity_source"]
                del request.session["combine_identity_target"]
                del request.session["combine_identity_source"]
                return redirect(
                    "identity-combine",
                    primary_pk=target,
                    secondary_pk=source,
                )
        return redirect("identity-detail", pk=self.object.pk)


class IdentityVerifyView(LoginRequiredMixin, DetailView):
    """
    Verify identity.
    """

    model = Identity
    template_name = "identity/identity_verify.html"
    candour_link: str = ""

    def get_candour_verification_method(self, candour_response: dict[str, Any]) -> Identity.VerificationMethod:
        """
        Return verification method strength based on Candour ID verification method.
        """
        if candour_response.get("verificationMethod") == "rfidApp":
            return Identity.VerificationMethod.STRONG
        elif candour_response.get("verificationMethod") in ["idApp", "idWeb"]:
            return Identity.VerificationMethod.PHOTO_ID
        return Identity.VerificationMethod.UNVERIFIED

    def update_candour_assurance_level(self, candour_response: dict[str, Any]) -> None:
        """
        Updates assurance level based on Candour ID verification method.
        """
        if candour_response.get("verificationMethod") == "rfidApp":
            assurance_level = Identity.AssuranceLevel.HIGH
        elif candour_response.get("verificationMethod") in ["idApp", "idWeb"]:
            assurance_level = Identity.AssuranceLevel.MEDIUM
        else:
            assurance_level = Identity.AssuranceLevel.NONE
        if self.object.assurance_level < assurance_level:
            self.object.assurance_level = assurance_level
            self.object.save()
            audit_log.info(
                f"Updated identity assurance level from Candour ID verification to {assurance_level}",
                category="identity",
                action="update",
                outcome="success",
                request=self.request,
                objects=[self.object],
                log_to_db=True,
            )

    def update_identifier(self, candour_response: dict[str, Any]) -> bool:
        """
        Updates or creates identifier based on Candour ID document.
        """
        try:
            id_document_type = candour_response["idDocumentType"][:2].replace("<", "")
            nationality = candour_response["nationality"]
            id_number = candour_response["idNumber"]
        except KeyError:
            audit_log.warning(
                "Candour ID verification response missing identifier information",
                category="identifier",
                action="create",
                outcome="failure",
                request=self.request,
                objects=[self.object],
                log_to_db=True,
            )
            return False
        identifier_value = f"{id_document_type}:{nationality}:{id_number}"
        try:
            valid_until = (
                datetime.strptime(candour_response.get("idExpiration", ""), "%Y-%m-%d").date()
                if candour_response.get("idExpiration")
                else None
            )
        except ValueError:
            valid_until = None
        identifier, created = self.object.identifiers.get_or_create(
            type=Identifier.Type.ID,
            value=identifier_value,
            valid_until=valid_until,
            defaults={"verified": timezone.now()},
        )
        if created:
            audit_log.info(
                f"Added identifier from Candour ID verification: {identifier_value}",
                category="identifier",
                action="create",
                outcome="success",
                request=self.request,
                objects=[self.object, identifier],
                log_to_db=True,
            )
        return True

    def update_identity_attributes(self, candour_response: dict[str, Any]) -> None:
        """
        Update identity attributes from Candour ID verification response.
        """
        fields = {
            "given_names": candour_response.get("firstName", ""),
            "surname": candour_response.get("lastName", ""),
            "date_of_birth": candour_response.get("dateOfBirth", ""),
            "nationality": candour_response.get("nationality", ""),
            "gender": candour_response.get("sex", ""),
        }
        verification_method = self.get_candour_verification_method(candour_response)
        if self.update_identifier(candour_response=candour_response):
            update_identity_attributes(self.request, self.object, fields, verification_method)
            self.update_candour_assurance_level(candour_response=candour_response)

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """
        Add account information to context data
        """
        context = super().get_context_data(**kwargs)
        context["suomifi_enabled"] = "kamu.backends.SuomiFiBackend" in settings.AUTHENTICATION_BACKENDS
        context["candour_enabled"] = getattr(settings, "CANDOUR_API", None) and settings.CANDOUR_API.get("URL", None)
        context["candour_link"] = self.candour_link
        context["assurance_level"] = {level.name: level.value for level in Identity.AssuranceLevel}
        return context

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """
        Check if user has active Candour ID verification and check it's status.
        """
        user = self.request.user
        if not user.is_authenticated:
            raise PermissionDenied
        self.object = self.get_object()
        if not self.object.user or self.object.user != user:
            raise PermissionDenied
        if (
            getattr(settings, "CANDOUR_API", None)
            and settings.CANDOUR_API.get("URL", None)
            and self.object.candour_verification_session_id
        ):
            try:
                candour_connector = CandourApiConnector()
                response = candour_connector.get_candour_result(
                    verification_session_id=self.object.candour_verification_session_id
                )
            except ApiError:
                messages.add_message(
                    self.request,
                    messages.ERROR,
                    _("Failed to verify Candour ID verification status, please try again."),
                )
                return super().get(request, *args, **kwargs)
            status = response.get("status")
            if status in ["pending", "opened", "started"]:
                self.candour_link = response.get("invitationLink", "")
            elif status == "finishedExpired":
                audit_log.info(
                    f"Candour ID session expired for {self.object}, session id "
                    f"{self.object.candour_verification_session_id}",
                    category="authentication",
                    action="update",
                    outcome="failure",
                    request=request,
                    objects=[self.object],
                    log_to_db=True,
                )
                self.object.candour_verification_session_id = ""
                self.object.save()
            else:
                if response.get("identityVerified"):
                    self.update_identity_attributes(response)
                    messages.add_message(
                        self.request,
                        messages.INFO,
                        _("Your identity has been verified with Candour ID verification."),
                    )
                    self.object.candour_verification_session_id = ""
                    self.object.save()
                    return redirect("identity-detail", pk=self.object.pk)
                else:
                    audit_log.info(
                        f"Candour ID verification failed for {self.object}",
                        category="authentication",
                        action="update",
                        outcome="failure",
                        request=request,
                        objects=[self.object],
                        log_to_db=True,
                    )
                    messages.add_message(
                        self.request,
                        messages.ERROR,
                        _("Candour ID verification failed, please try again."),
                    )
                    self.object.candour_verification_session_id = ""
                    self.object.save()
        return super().get(request, *args, **kwargs)

    @method_decorator(csrf_protect)
    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """
        Check redirection to either Suomi.fi or Candour ID verification.
        """
        self.object = self.get_object()
        data = self.request.POST
        if "verify_identity" in data and self.request.user == self.object.user:
            verify_type = str(data["verify_identity"])
            if verify_type == "suomifi":
                self.request.session["link_identifier"] = True
                self.request.session["link_identifier_time"] = timezone.now().isoformat()
                linking_url = (
                    reverse("login-suomifi") + "?next=" + reverse("identity-detail", kwargs={"pk": self.object.pk})
                )
                return HttpResponseRedirect(linking_url)
            if verify_type == "candour" or verify_type == "candour_low":
                if verify_type == "candour_low":
                    verification_methods = ["idWeb", "idApp"]
                else:
                    verification_methods = ["rfidApp"]
                try:
                    candour_connector = CandourApiConnector()
                    response = candour_connector.create_candour_session(
                        identity=self.object, valid_hours=1, verification_methods=verification_methods
                    )
                except ApiError:
                    messages.add_message(
                        self.request,
                        messages.ERROR,
                        _("Failed to create Candour ID verification session, please try again."),
                    )
                    return redirect("identity-verify", pk=self.object.pk)
                redirect_url = response.get("redirectUrl")
                verification_session_id = response.get("verificationSessionId")
                if not redirect_url or not verification_session_id:
                    messages.add_message(
                        self.request, messages.ERROR, _("Could not start Candour ID process, please try again later.")
                    )
                    return redirect("identity-verify", pk=self.object.pk)
                audit_log.info(
                    f"Created Candour ID session: {verification_session_id}",
                    category="authentication",
                    action="create",
                    outcome="success",
                    request=request,
                    objects=[self.object],
                    log_to_db=True,
                )
                self.object.candour_verification_session_id = verification_session_id
                self.object.save()
                return redirect(redirect_url)
        return redirect("identity-verify", pk=self.object.pk)


class IdentityUpdateView(LoginRequiredMixin, UpdateView):
    model = Identity
    form_class = IdentityForm
    template_name = "identity/identity_form.html"

    def form_valid(self, form: IdentityForm) -> HttpResponse:
        """
        Set verification level to self-asserted, if user is changing their own information.
        """
        if self.request.user == self.object.user:
            for field in form.changed_data:
                if (
                    field in self.object.verifiable_fields()
                    and getattr(form.instance, f"{field}_verification") != Identity.VerificationMethod.SELF_ASSURED
                ):
                    setattr(form.instance, f"{field}_verification", Identity.VerificationMethod.SELF_ASSURED)
        valid = super().form_valid(form)
        remove_nationality = form.cleaned_data.get("remove_nationality")
        if remove_nationality:
            for nationality in remove_nationality:
                audit_log.info(
                    f"Will remove nationality {nationality.country.code}",
                    category="identity",
                    action="update",
                    outcome="success",
                    request=self.request,
                    objects=[self.object],
                    log_to_db=True,
                )
                nationality.delete()
        add_nationality = form.cleaned_data.get("add_nationality")
        if add_nationality:
            verification_method = (
                form.cleaned_data.get("add_nationality_verification") or Identity.VerificationMethod.SELF_ASSURED
            )
            nationality, created = self.object.nationalities.get_or_create(
                country=add_nationality, defaults={"verification_method": verification_method}
            )
            if created:
                audit_log.info(
                    f"Added nationality {nationality.country.code}",
                    category="identity",
                    action="update",
                    outcome="success",
                    request=self.request,
                    objects=[self.object],
                    log_to_db=True,
                )
        if form.changed_data:
            # construct_change_message is used for all models in admin, but limited to single form in django-stubs.
            change_message = construct_change_message(form, [], False)  # type: ignore[arg-type]
            audit_log.info(
                "Changed identity information",
                category="identity",
                action="update",
                outcome="success",
                request=self.request,
                objects=[self.object],
                log_to_db=True,
                db_message=change_message,
            )
        return valid

    def get_form_kwargs(self) -> dict[str, Any]:
        """
        Add request object to the form class.
        """
        kwargs = super().get_form_kwargs()
        kwargs["request"] = self.request
        return kwargs

    def get_queryset(self) -> QuerySet[Identity]:
        """
        Restrict update to user's own information, unless user has permission to modify all basic information.
        """
        queryset = super().get_queryset()
        if not self.request.user.has_perms(["kamu.change_basic_information"]):
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


class EmailAddressVerificationView(BaseVerificationView):
    """
    A view for verifying an email address
    """

    form_class = EmailAddressVerificationForm
    template_name = "identity/email_address_verification.html"
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
        subject = _("Kamu: email address verification")
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

    def form_valid(self, form: BaseForm) -> HttpResponse:
        """
        Verify a contact if code was correct.
        """
        create_or_verify_email_address(request=self.request, identity=self.object.identity, email_object=self.object)
        return super().form_valid(form)


class PhoneNumberVerificationView(BaseVerificationView):
    """
    A view for verifying a phone number.
    """

    form_class = PhoneNumberVerificationForm
    template_name = "identity/phone_number_verification.html"
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

    def form_valid(self, form: BaseForm) -> HttpResponse:
        """
        Verify a contact if code was correct.
        """
        create_or_verify_phone_number(request=self.request, identity=self.object.identity, phone_object=self.object)
        return super().form_valid(form)


class ContactView(LoginRequiredMixin, FormView):
    """
    List contact addresses and add new contact addresses.
    """

    form_class = ContactForm
    template_name = "identity/contact_address.html"
    success_url = "#"

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponseBase:
        user = self.request.user if self.request.user.is_authenticated else None
        if not user:
            raise PermissionDenied
        try:
            self.identity = Identity.objects.get(pk=self.kwargs.get("pk"))
        except Identity.DoesNotExist:
            raise PermissionDenied
        if self.identity.user != user and not user.has_perms(["kamu.change_contacts"]):
            raise PermissionDenied
        return super().dispatch(request, *args, **kwargs)

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """
        Log listing contact information.
        """
        get = super().get(request, *args, **kwargs)
        audit_log.info(
            "Listed contact information",
            category="contact",
            action="read",
            outcome="success",
            request=self.request,
            objects=[self.identity],
        )
        return get

    def get_form_kwargs(self) -> dict[str, Any]:
        """
        Add identity object to the form class.
        """
        kwargs = super().get_form_kwargs()
        kwargs["identity"] = self.identity
        return kwargs

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """
        Add lists of users email_addresses and phone_numbers to context.
        """
        context = super().get_context_data(**kwargs)
        identity = Identity.objects.get(pk=self.kwargs.get("pk"))
        context["identity"] = identity
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
            email_object = EmailAddress.objects.create(
                identity=form.identity, address=form.cleaned_data["contact"], priority=priority
            )
            audit_log.info(
                "Added email address",
                category="email_address",
                action="create",
                outcome="success",
                request=self.request,
                objects=[email_object, form.identity],
                log_to_db=True,
            )
        if form.cleaned_data["contact_type"] == "phone":
            last_phone = PhoneNumber.objects.filter(identity=form.identity).order_by("priority").last()
            priority = last_phone.priority + 1 if last_phone else 0
            phone_object = PhoneNumber.objects.create(
                identity=form.identity, number=form.cleaned_data["contact"], priority=priority
            )
            audit_log.info(
                "Added phone number",
                category="phone_number",
                action="create",
                outcome="success",
                request=self.request,
                objects=[phone_object, form.identity],
                log_to_db=True,
            )
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
        changed = False
        primary_email_address = self.identity.email_address()
        if "phone_remove" in data:
            pk = int(data["phone_remove"])
            try:
                phone_number = PhoneNumber.objects.get(pk=pk, identity=self.identity)
                audit_log.info(
                    "Deleted phone number",
                    category="phone_number",
                    action="delete",
                    outcome="success",
                    request=self.request,
                    objects=[phone_number, self.identity],
                    log_to_db=True,
                )
                phone_number.delete()
            except PhoneNumber.DoesNotExist:
                pass
            changed = True
        elif "email_remove" in data:
            pk = int(data["email_remove"])
            try:
                email_address = EmailAddress.objects.filter(pk=pk, identity=self.identity)
                audit_log.info(
                    "Deleted email address",
                    category="email_address",
                    action="delete",
                    outcome="success",
                    request=self.request,
                    objects=[email_address, self.identity],
                    log_to_db=True,
                )
                email_address.delete()
            except EmailAddress.DoesNotExist:
                pass
            changed = True
        elif "email_up" in data:
            pk = int(data["email_up"])
            self._change_contact_priority(EmailAddress, pk, "up")
            changed = True
        elif "email_down" in data:
            pk = int(data["email_down"])
            self._change_contact_priority(EmailAddress, pk, "down")
            changed = True
        elif "phone_up" in data:
            pk = int(data["phone_up"])
            self._change_contact_priority(PhoneNumber, pk, "up")
            changed = True
        elif "phone_down" in data:
            pk = int(data["phone_down"])
            self._change_contact_priority(PhoneNumber, pk, "down")
            changed = True
        if changed:
            new_primary_email_address = self.identity.email_address()
            if primary_email_address and primary_email_address != new_primary_email_address:
                audit_log.info(
                    f"Changed primary email address to {new_primary_email_address}",
                    category="email_address",
                    action="update",
                    outcome="success",
                    request=self.request,
                    objects=[self.identity],
                    log_to_db=True,
                )
                send_primary_email_changed_notification(
                    self.identity, primary_email_address, actor_self=self.identity.user == self.request.user
                )
            return redirect("contact-change", pk=self.identity.pk)
        return super().post(request, *args, **kwargs)


class ContractListView(LoginRequiredMixin, ListView[Contract]):
    """
    List contracts for an identity.
    """

    template_name = "contract/contract_list.html"
    success_url = "#"

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponseBase:
        """
        Restricts identity to logged-in user unless user has permission to view all contracts.
        """
        user = self.request.user if self.request.user.is_authenticated else None
        if not user:
            raise PermissionDenied
        try:
            self.identity = Identity.objects.get(pk=self.kwargs.get("pk"))
        except Identity.DoesNotExist:
            raise PermissionDenied
        if self.identity.user != user and not user.has_perms(["kamu.view_contracts"]):
            raise PermissionDenied
        return super().dispatch(request, *args, **kwargs)

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """
        Log listing contract information.
        """
        get = super().get(request, *args, **kwargs)
        audit_log.info(
            "Listed contract information",
            category="contract",
            action="read",
            outcome="success",
            request=self.request,
            objects=[self.identity],
        )
        return get

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """
        Add identity and the list of signable contracts to context.

        Signable contracts are the latest version of each public contract type, that the user has not signed.
        """
        context = super().get_context_data(**kwargs)
        context["identity"] = Identity.objects.get(pk=self.kwargs.get("pk"))
        type_query = ContractTemplate.objects.filter(public=True, type=OuterRef("type")).order_by("-version")
        context["signable_list"] = (
            ContractTemplate.objects.filter(pk=Subquery(type_query.values("pk")[:1]))
            .exclude(pk__in=context["contract_list"].values_list("template__pk"))
            .order_by("type")
        )
        return context

    def get_queryset(self) -> QuerySet[Contract]:
        """
        List user's contracts. If list_all is given as a GET parameter, list all contracts,
        otherwise list only the latest version of each contract type.
        """
        list_all = self.request.GET.get("list_all")
        if list_all:
            queryset = Contract.objects.filter(identity__pk=self.kwargs.get("pk")).order_by(
                "template__type", "-template__version"
            )
        else:
            type_query = Contract.objects.filter(
                identity__pk=self.kwargs.get("pk"), template__type=OuterRef("template__type")
            ).order_by("-template__version")
            queryset = (
                Contract.objects.filter(identity__pk=self.kwargs.get("pk"))
                .filter(pk=Subquery(type_query.values("pk")[:1]))
                .order_by("template__type")
            )
        return queryset


class ContractSignView(LoginRequiredMixin, TemplateView):
    """
    Sign contract.
    """

    template_name = "contract/contract_sign.html"

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponseBase:
        """
        Restricts identity to logged-in user.
        """
        user = self.request.user if self.request.user.is_authenticated else None
        if not user:
            raise PermissionDenied
        try:
            identity = Identity.objects.get(pk=self.kwargs.get("identity_pk"))
            ContractTemplate.objects.get(pk=self.kwargs.get("template_pk"))
        except ObjectDoesNotExist:
            raise PermissionDenied
        if identity.user != user:
            raise PermissionDenied
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """
        Add contract template and identity to context data.
        """
        context = super().get_context_data(**kwargs)
        context["identity"] = Identity.objects.get(pk=self.kwargs.get("identity_pk"))
        context["template"] = ContractTemplate.objects.get(pk=self.kwargs.get("template_pk"))
        context["date"] = timezone.now().date()
        return context

    @method_decorator(csrf_protect)
    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """
        Signs a contract.
        """
        data = self.request.POST
        identity = Identity.objects.get(pk=self.kwargs.get("identity_pk"))
        if "sign_contract" in data:
            template_pk = int(data["sign_contract"])
            template = ContractTemplate.objects.get(pk=self.kwargs.get("template_pk"))
            if template_pk != template.pk:
                raise PermissionDenied
            try:
                contract = Contract.objects.sign_contract(template=template, identity=identity)
                audit_log.info(
                    f"Contract {contract.template.type}-{contract.template.version} signed",
                    category="contract",
                    action="create",
                    outcome="success",
                    request=self.request,
                    objects=[contract, identity, template, request.user],
                    log_to_db=True,
                )
            except IntegrityError:
                messages.add_message(self.request, messages.WARNING, _("Contract already signed."))
                return redirect("contract-list", pk=identity.pk)
            except ValueError:
                messages.add_message(
                    self.request,
                    messages.WARNING,
                    _("Contract version has changed. Please try again."),
                )
                return redirect("contract-list", pk=identity.pk)
            messages.add_message(self.request, messages.INFO, _("Contract signed."))
            return redirect("identity-detail", pk=identity.pk)
        return redirect("contract-list", pk=identity.pk)


class ContractDetailView(LoginRequiredMixin, DetailView):
    """
    View for the contract details.
    """

    model = Contract
    template_name = "contract/contract_detail.html"

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """
        Log viewing contract information.
        """
        get = super().get(request, *args, **kwargs)
        audit_log.info(
            "Read contract information",
            category="contract",
            action="read",
            outcome="success",
            request=self.request,
            objects=[self.object, self.object.identity],
        )
        return get

    def get_queryset(self) -> QuerySet[Identity]:
        """
        Restrict access to user's own contracts, unless user has permission to view all contracts,
        """
        queryset = super().get_queryset()
        if not self.request.user.has_perms(["kamu.view_contracts"]):
            queryset = queryset.filter(identity__user=self.request.user)
        return queryset


class IdentifierView(LoginRequiredMixin, TemplateView):
    """
    List and deactivate identifiers.
    """

    template_name = "identity/identifier.html"

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
        if self.identity.user != user and not user.has_perms(["kamu.view_identifiers"]):
            raise PermissionDenied
        if (
            request.method
            and request.method.lower() == "post"
            and self.identity.user != user
            and not user.has_perms(["identity.change_identifiers"])
        ):
            raise PermissionDenied
        return super().dispatch(request, *args, **kwargs)

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """
        Log listing identifier information.
        """
        get = super().get(request, *args, **kwargs)
        audit_log.info(
            "Listed identifier information",
            category="identifier",
            action="read",
            outcome="success",
            request=self.request,
            objects=[self.identity],
        )
        return get

    def get_list_of_identifiers_user_cannot_deactivate(self) -> set[int]:
        """
        Get a set of identifiers that the user cannot deactivate.

        If the user does not have generic change_identifiers permission,
        prevent deactivation of last active identifier.

        Also prevent deactivation of FPIC and local EPPN identifiers.
        """
        if self.request.user.has_perms(["kamu.change_identifiers"]):
            return set()
        active_identifiers = Identifier.objects.filter(identity=self.identity, deactivated_at__isnull=True)
        if self.identity.user != self.request.user or active_identifiers.count() <= 1:
            return {identifier.pk for identifier in active_identifiers}
        return {
            identifier.pk
            for identifier in active_identifiers
            if (
                identifier.type == Identifier.Type.FPIC
                or (identifier.type == Identifier.Type.EPPN and identifier.value.endswith(settings.LOCAL_EPPN_SUFFIX))
            )
        }

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """
        Add lists of users email_addresses and phone_numbers to context.
        """
        context = super().get_context_data(**kwargs)
        identity = Identity.objects.get(pk=self.kwargs.get("pk"))
        context["identifier_active_list"] = Identifier.objects.filter(identity=identity, deactivated_at=None)
        context["identifier_deactivated_list"] = Identifier.objects.filter(
            identity=identity, deactivated_at__isnull=False
        )
        context["cannot_deactivate_list"] = self.get_list_of_identifiers_user_cannot_deactivate()
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
                logout_url = f"{oidc_logout_path}{quote_plus(service_link_url)}{quote_plus(linking_url)}"
            else:
                logout_url = f"{oidc_logout_path}{quote_plus(linking_url)}"
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
            if pk in self.get_list_of_identifiers_user_cannot_deactivate():
                raise PermissionDenied
            try:
                identifier = Identifier.objects.get(pk=pk, identity=self.identity, deactivated_at__isnull=True)
                identifier.deactivated_at = timezone.now()
                identifier.save()
                audit_log.info(
                    "Deactivated identifier",
                    category="identifier",
                    action="unlink",
                    outcome="success",
                    request=self.request,
                    objects=[identifier, self.identity],
                    log_to_db=True,
                )
            except Identifier.DoesNotExist:
                pass
        elif "link_identifier" in data and self.request.user == self.identity.user:
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
                given_names_verification=Identity.VerificationMethod.EXTERNAL,
                surname=user.last_name,
                surname_verification=Identity.VerificationMethod.EXTERNAL,
            )
            if user.email:
                EmailAddress.objects.create(address=user.email, identity=identity)
            messages.add_message(request, messages.WARNING, _("New identity created."))
        return redirect("identity-detail", pk=identity.pk)


class IdentityMeVerifyView(LoginRequiredMixin, View):
    """
    Redirect to current user's verify view.
    """

    def get(self, request: HttpRequest) -> HttpResponse:
        """
        Redirects user to their own identity verify page.
        Used as a redirect target after external identity verify.
        """
        user = self.request.user if self.request.user.is_authenticated else None
        if not user:
            raise PermissionDenied
        try:
            identity = Identity.objects.get(user=user)
        except Identity.DoesNotExist:
            raise PermissionDenied
        session_id = request.GET.get("sessionId")
        status = request.GET.get("status")
        if session_id and session_id != identity.candour_verification_session_id:
            messages.add_message(request, messages.ERROR, _("Invalid verification session."))
            audit_log.warning(
                f"Invalid Candour session ID {identity}, user's session ID: "
                f"{identity.candour_verification_session_id}, returned session ID: {session_id}",
                category="identity",
                action="update",
                outcome="failure",
                request=request,
                objects=[identity],
                log_to_db=True,
            )
            raise PermissionDenied
        if status in ["cancelled", "cancelledUnsupportedDevice", "cancelledUnsupportedId"]:
            messages.add_message(request, messages.WARNING, _("Identity verification was cancelled."))
        return redirect("identity-verify", pk=identity.pk)


class IdentitySearchView(LoginRequiredMixin, ListView[Identity]):
    """
    Identity search view with results list.
    """

    template_name = "identity/identity_search.html"
    model = Identity

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """
        Initialize exact match variables.
        """
        super().__init__()
        self.exact_match_found = False
        self.exact_match_skip = getattr(settings, "SKIP_NAME_SEARCH_IF_IDENTIFIER_MATCHES", True)

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponseBase:
        """
        Check that user has permission to search identities.
        """
        if not self.request.user.has_perm("kamu.search_identities"):
            raise PermissionDenied
        return super().dispatch(request, *args, **kwargs)

    def _ldap_search_attribute(self, attribute: dict[str, LdapSearchAttributeType]) -> list | None:
        """
        Search LDAP for attribute(s).

        attribute is the list of tuples containing LDAP attribute name, URL parameter name and wildcard boolean.

        Return empty list if no search parameters are found.
        Return None if LDAP search does not succeed.
        """
        ldap_parameters = []
        ldap_values = []
        for param, conf in attribute.items():
            ldap_name = str(conf.get("attribute"))
            wildcard = conf.get("wildcard", False)
            value_prefix = conf.get("value_prefix", "")
            value = self.parse_search_attribute(param)
            if not value:
                continue
            if wildcard:
                ldap_parameters.append("(" + ldap_name + "=*{}*)")
            else:
                ldap_parameters.append("(" + ldap_name + "={})")
            ldap_values.append(f"{value_prefix}{value}")
        if not ldap_parameters:
            return []
        try:
            ldap_result = ldap_search(search_filter="(&" + "".join(ldap_parameters) + ")", search_values=ldap_values)
        except LDAP_SIZELIMIT_EXCEEDED:
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

        Return empty list if no results are found.
        Return None if LDAP search does not succeed.
        """
        results: set = set()
        search_attributes = settings.LDAP_SEARCH_ATTRIBUTES
        for key, value in search_attributes.items():
            if key == "names" and self.exact_match_skip and self.exact_match_found:
                continue
            search_result = self._ldap_search_attribute(value)
            if key != "names" and search_result:
                self.exact_match_found = True
            if search_result is None:
                return None
            else:
                results |= set(frozenset(res.items()) for res in search_result)
        return [dict(res) for res in results]

    @staticmethod
    def _filter_ldap_list(object_list: QuerySet[Identity], ldap_results: list) -> list:
        """
        Filter out LDAP results where uid does not exist or is already in object_list, and sort results.
        """
        result_uids = set(object_list.values_list("uid", flat=True))
        return sorted(
            [res for res in ldap_results if res.get("uid") and res["uid"] not in result_uids],
            key=lambda x: x.get("cn", ""),
        )

    @staticmethod
    def search_ldap() -> bool:
        """
        Check if LDAP should be searched.
        """
        return getattr(settings, "LDAP_SEARCH_FOR_IDENTITIES", False)

    def log_search(self) -> None:
        """
        Log search terms.
        """
        search_terms = {}
        for term in ["given_names", "surname", "email", "phone", "uid", "fpic"]:
            value = self.parse_search_attribute(term)
            if value:
                search_terms[term] = value
        audit_log.info(
            "Searched identities",
            category="identity",
            action="search",
            outcome="success",
            request=self.request,
            extra={"search_terms": str(search_terms), "ldap": self.search_ldap()},
        )

    def build_queryset_identifiers(self, fpic: str, uid: str, email: str, phone: str) -> QuerySet[Identity]:
        """
        Build queryset with identifier search terms.
        """
        queryset = Identity.objects.none()
        if fpic:
            queryset = queryset.union(Identity.objects.filter(fpic=fpic))
            queryset = queryset.union(
                Identity.objects.filter(identifiers__type=Identifier.Type.FPIC, identifiers__value=fpic)
            )
        if uid:
            queryset = queryset.union(Identity.objects.filter(uid=uid))
        if email:
            queryset = queryset.union(Identity.objects.filter(email_addresses__address__iexact=email))
        if phone:
            phone = phone.replace(" ", "")
            queryset = queryset.union(Identity.objects.filter(phone_numbers__number__exact=phone))
        return queryset

    def build_queryset_names(self, given_names: str, surname: str, exact_matches: bool = False) -> QuerySet[Identity]:
        """
        Build queryset with name search terms, with an option to limit to exact matches.
        """
        queryset = Identity.objects.all()
        if given_names:
            if exact_matches:
                queryset = queryset.filter(
                    Q(given_names__iexact=given_names) | Q(given_name_display__iexact=given_names)
                )
            else:
                queryset = queryset.filter(
                    Q(given_names__icontains=given_names) | Q(given_name_display__icontains=given_names)
                )
        if surname:
            if exact_matches:
                queryset = queryset.filter(Q(surname__iexact=surname) | Q(surname_display__iexact=surname))
            else:
                queryset = queryset.filter(Q(surname__icontains=surname) | Q(surname_display__icontains=surname))
        return queryset

    def name_search(self, given_names: str, surname: str) -> QuerySet[Identity]:
        """
        Search identities based on names.
        """
        queryset = self.build_queryset_names(given_names=given_names, surname=surname)
        if queryset.count() > getattr(settings, "KAMU_IDENTITY_SEARCH_LIMIT", 50):
            queryset = self.build_queryset_names(given_names=given_names, surname=surname, exact_matches=True)
            if queryset.count() > getattr(settings, "KAMU_IDENTITY_SEARCH_LIMIT", 50):
                messages.add_message(
                    self.request,
                    messages.WARNING,
                    _("Too many results, please refine your search parameters."),
                )
                queryset = Identity.objects.none()
            else:
                messages.add_message(
                    self.request,
                    messages.WARNING,
                    _("Partial name matches returned too many results. Returning only exact matches."),
                )
        return queryset

    def parse_search_attribute(self, attribute_type: str) -> str:
        """
        Parses attribute value from URL parameters.

        Returns identifiers only if identifier value is valid for attribute_type.
        """
        if attribute_type == "given_names":
            return self.request.POST.get("given_names", "").strip()
        if attribute_type == "surname":
            return self.request.POST.get("surname", "").strip()
        identifier = self.request.POST.get("identifier", "")
        if not identifier:
            return ""
        match attribute_type:
            case "phone":
                try:
                    phone = identifier.strip().replace(" ", "")
                    validate_phone_number(phone)
                    return phone
                except ValidationError:
                    return ""
            case "email":
                try:
                    email = identifier.strip()
                    validate_email(email)
                    return email
                except ValidationError:
                    return ""
            case "fpic":
                try:
                    fpic = identifier.strip()
                    validate_fpic(fpic)
                    return fpic
                except ValidationError:
                    return ""
            case "uid":
                uid_characters = set(string.ascii_lowercase + string.digits + "_")
                uid = identifier.strip().lower()
                if set(uid).issubset(uid_characters):
                    return uid
        return ""

    def search_results(self) -> dict[str, Any]:
        """
        Search Kamu and user directory based on URL parameters.

        Limit search results to identifier matches if exact_match_skip is True and exact match is found.
        """
        given_names = self.parse_search_attribute("given_names")
        surname = self.parse_search_attribute("surname")
        fpic = self.parse_search_attribute("fpic")
        uid = self.parse_search_attribute("uid")
        email = self.parse_search_attribute("email")
        phone = self.parse_search_attribute("phone")
        queryset = self.build_queryset_identifiers(fpic=fpic, uid=uid, email=email, phone=phone)
        if queryset.exists():
            self.exact_match_found = True
        ldap_results = None
        if self.search_ldap():
            ldap_results = self._get_ldap_results()
            if ldap_results is None:
                messages.add_message(
                    self.request, messages.ERROR, _("LDAP search failed, could not search existing accounts.")
                )
        if (given_names or surname) and not (self.exact_match_skip and self.exact_match_found):
            queryset = queryset.union(self.name_search(given_names=given_names, surname=surname))
        elif given_names or surname:
            messages.add_message(
                self.request,
                messages.INFO,
                _("Identifier match found, skipping name search."),
            )
        if ldap_results and getattr(settings, "FILTER_KAMU_RESULTS_FROM_LDAP_RESULTS", True):
            ldap_results = self._filter_ldap_list(queryset, ldap_results)
        self.log_search()
        return {"object_list": queryset, "ldap_results": ldap_results}

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """
        Add form and searched phone and email to context data.
        """
        context = super().get_context_data(**kwargs)
        if "reset_form" in self.request.POST:
            context["form"] = IdentitySearchForm(use_ldap=self.search_ldap())
            return context
        context["phone"] = self.parse_search_attribute("phone")
        context["email"] = self.parse_search_attribute("email")
        context["fpic"] = self.parse_search_attribute("fpic")
        context["uid"] = self.parse_search_attribute("uid")
        context["form"] = IdentitySearchForm(self.request.POST, use_ldap=self.search_ldap())
        if (
            self.request.method == "POST"
            and IdentitySearchForm(self.request.POST, use_ldap=self.search_ldap()).is_valid()
        ):
            context.update(self.search_results())
        return context

    def get_queryset(self) -> QuerySet[Identity]:
        """
        Return empty queryset. Required for ListView but overwritten in get_context_data.
        """
        return Identity.objects.none()

    @method_decorator(csrf_protect)
    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """
        Allow post method to be used in a same way as get method.
        """
        self.object_list = self.get_queryset()
        context = self.get_context_data()
        return self.render_to_response(context)


class IdentityCombineView(LoginRequiredMixin, TemplateView):
    """
    Combines two identities.
    """

    template_name = "identity/identity_combine.html"

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponseBase:
        user = self.request.user if self.request.user.is_authenticated else None
        if not user or not user.has_perms(["kamu.combine_identities"]):
            raise PermissionDenied
        try:
            self.primary_identity = Identity.objects.get(pk=self.kwargs.get("primary_pk"))
            self.secondary_identity = Identity.objects.get(pk=self.kwargs.get("secondary_pk"))
        except Identity.DoesNotExist:
            raise PermissionDenied
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """
        Add identities to context data.
        """
        context = super().get_context_data(**kwargs)
        context["primary_identity"] = self.primary_identity
        context["secondary_identity"] = self.secondary_identity
        context["form"] = IdentityCombineForm()
        return context

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """
        Test requirements for combining identities.
        """
        permissions = set(self.request.user.get_all_permissions()).intersection(
            {
                "identity.view_basic_information",
                "identity.view_restricted_information",
                "identity.view_contacts",
                "identity.view_contracts",
                "identity.view_identifiers",
            }
        )
        for identity in [self.primary_identity, self.secondary_identity]:
            audit_log.info(
                "Read identity information",
                category="identity",
                action="read",
                outcome="success",
                request=self.request,
                objects=[identity],
                extra={"permissions": str(permissions)},
            )
        combine_identities_requirements(self.request, self.primary_identity, self.secondary_identity)
        return super().get(request, *args, **kwargs)

    @method_decorator(csrf_protect)
    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """
        Combine identities.
        """
        data = self.request.POST
        if "combine" in data and combine_identities_requirements(
            request, self.primary_identity, self.secondary_identity
        ):
            primary = int(data["primary_identity"])
            secondary = int(data["secondary_identity"])
            if primary != self.primary_identity.pk or secondary != self.secondary_identity.pk:
                messages.add_message(
                    self.request,
                    messages.WARNING,
                    _("Incorrect primary keys."),
                )
                return redirect(
                    "identity-combine", primary_pk=self.primary_identity.pk, secondary_pk=self.secondary_identity.pk
                )
            combine_identities(self.request, self.primary_identity, self.secondary_identity)
            messages.add_message(self.request, messages.INFO, _("Identities combined."))
            return redirect("identity-detail", pk=self.primary_identity.pk)
        raise PermissionDenied
