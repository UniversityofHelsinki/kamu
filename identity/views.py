"""
Identity app views for the UI.
"""

from typing import Any
from urllib.parse import quote_plus

from django.conf import settings
from django.contrib import messages
from django.contrib.admin.utils import construct_change_message
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.models import Group
from django.core.exceptions import ObjectDoesNotExist, PermissionDenied
from django.core.mail import send_mail
from django.db import IntegrityError, transaction
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

from base.connectors.ldap import LDAP_SIZELIMIT_EXCEEDED, ldap_search
from base.connectors.sms import SmsConnector
from base.models import TimeLimitError, Token
from base.utils import AuditLog
from identity.forms import (
    ContactForm,
    EmailAddressVerificationForm,
    IdentityCombineForm,
    IdentityForm,
    IdentitySearchForm,
    PhoneNumberVerificationForm,
)
from identity.models import (
    Contract,
    ContractTemplate,
    EmailAddress,
    Identifier,
    Identity,
    PhoneNumber,
)
from identity.utils import combine_identities, combine_identities_requirements
from role.models import Membership
from role.utils import add_missing_requirement_messages

audit_log = AuditLog()


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
        return get

    @method_decorator(csrf_protect)
    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """
        Check for combine identity posts.
        """
        self.object = self.get_object()
        if (
            "combine_target" in self.request.POST or "combine_source" in self.request.POST
        ) and self.request.user.has_perms(["identity.combine_identities"]):
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


class IdentityUpdateView(UpdateView):
    model = Identity
    form_class = IdentityForm

    def form_valid(self, form: IdentityForm) -> HttpResponse:
        """
        Set verification level to self-asserted, if user is changing their own information.
        """
        if self.request.user == self.object.user:
            for field in form.changed_data:
                if field in self.object.verifiable_fields() and getattr(form.instance, f"{field}_verification") != 1:
                    setattr(form.instance, f"{field}_verification", 1)
        valid = super().form_valid(form)
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
        if not self.object.verified:
            with transaction.atomic():
                self.object.verified = True
                self.object.save()
                if isinstance(self.object, EmailAddress):
                    audit_log.info(
                        "Verified email address",
                        category="email_address",
                        action="update",
                        outcome="success",
                        request=self.request,
                        objects=[self.object, self.object.identity],
                        log_to_db=True,
                    )
                    for email_obj in EmailAddress.objects.filter(address=self.object.address, verified=True).exclude(
                        pk=self.object.pk
                    ):
                        email_obj.verified = False
                        email_obj.save()
                        audit_log.warning(
                            "Removed verification from the email address as the address was verified elsewhere",
                            category="email_address",
                            action="update",
                            outcome="success",
                            request=self.request,
                            objects=[email_obj, email_obj.identity],
                            log_to_db=True,
                        )
                if isinstance(self.object, PhoneNumber):
                    audit_log.info(
                        "Verified phone number",
                        category="phone_number",
                        action="update",
                        outcome="success",
                        request=self.request,
                        objects=[self.object, self.object.identity],
                        log_to_db=True,
                    )
                    for phone_obj in PhoneNumber.objects.filter(number=self.object.number, verified=True).exclude(
                        pk=self.object.pk
                    ):
                        phone_obj.verified = False
                        phone_obj.save()
                        audit_log.warning(
                            "Removed verification from the phone number as the number was verified elsewhere",
                            category="phone_number",
                            action="update",
                            outcome="success",
                            request=self.request,
                            objects=[phone_obj, phone_obj.identity],
                            log_to_db=True,
                        )
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
            return redirect("contact-change", pk=self.identity.pk)
        if "email_remove" in data:
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
        if self.identity.user != user and not user.has_perms(["identity.view_contracts"]):
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
        context = super(ContractListView, self).get_context_data(**kwargs)
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
        context = super(ContractSignView, self).get_context_data(**kwargs)
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
                    f"Contract { contract.template.type }-{ contract.template.version } signed",
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
            return redirect("contract-detail", pk=contract.pk)
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
        queryset = super(ContractDetailView, self).get_queryset()
        if not self.request.user.has_perms(["identity.view_contracts"]):
            queryset = queryset.filter(identity__user=self.request.user)
        return queryset


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

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponseBase:
        if not self.request.user.has_perm("identity.search_identities"):
            raise PermissionDenied
        return super().dispatch(request, *args, **kwargs)

    def _ldap_search_attribute(self, attribute: list[tuple[str, str, bool]]) -> list | None:
        """
        Search LDAP for attribute(s).

        attribute is the list of tuples containing LDAP attribute name, URL parameter name and wildcard boolean.

        Return empty list if no search parameters are found.
        Return None if LDAP search does not succeed.
        """
        ldap_parameters = []
        ldap_values = []
        for attr in attribute:
            ldap_name, param_name, wildcard = attr
            value = self.request.GET.get(param_name)
            if not value:
                continue
            if wildcard:
                ldap_parameters.append("(" + ldap_name + "=*{}*)")
            else:
                ldap_parameters.append("(" + ldap_name + "={})")
            ldap_values.append(value)
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

    @staticmethod
    def search_ldap() -> bool:
        """
        Check if LDAP should be searched.
        """
        return False

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """
        Add form and searched phone and email to context data.
        """
        context = super(IdentitySearchView, self).get_context_data(**kwargs)
        context["phone"] = self.request.GET.get("phone", "").replace(" ", "")
        context["email"] = self.request.GET.get("email")
        context["form"] = IdentitySearchForm(self.request.GET)
        if self.search_ldap():
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
        search_terms = {}
        if not given_names and not surname:
            queryset = queryset.none()
        if given_names:
            queryset = queryset.filter(
                Q(given_names__icontains=given_names) | Q(given_name_display__icontains=given_names)
            )
            search_terms["given_names"] = given_names
        if surname:
            queryset = queryset.filter(Q(surname__icontains=surname) | Q(surname_display__icontains=surname))
            search_terms["surname"] = surname
        if email:
            queryset = queryset.union(Identity.objects.filter(email_addresses__address__iexact=email))
            search_terms["email"] = email
        if uid:
            queryset = queryset.union(Identity.objects.filter(uid=uid))
            search_terms["uid"] = uid
        if phone:
            phone = phone.replace(" ", "")
            queryset = queryset.union(Identity.objects.filter(phone_numbers__number__exact=phone))
            search_terms["phone"] = phone
        audit_log.info(
            "Searched identities",
            category="identity",
            action="search",
            outcome="success",
            request=self.request,
            extra={"search_terms": str(search_terms), "ldap": self.search_ldap()},
        )
        return queryset


class IdentityCombineView(LoginRequiredMixin, TemplateView):
    """
    Combines two identities.
    """

    template_name = "identity/identity_combine.html"

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponseBase:
        user = self.request.user if self.request.user.is_authenticated else None
        if not user or not user.has_perms(["identity.combine_identities"]):
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
