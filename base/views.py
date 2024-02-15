"""
Base views, shared between apps.
"""

import logging
from datetime import datetime, timedelta
from typing import Any

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import get_user_model
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.models import User as UserType
from django.contrib.auth.views import LoginView, LogoutView
from django.core.exceptions import PermissionDenied
from django.http import (
    Http404,
    HttpRequest,
    HttpResponse,
    HttpResponseBase,
    HttpResponseRedirect,
)
from django.shortcuts import redirect, render
from django.urls import reverse
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.utils.translation import get_language
from django.utils.translation import gettext as _
from django.views import View
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.debug import sensitive_post_parameters
from django.views.generic import FormView

from base.auth import (
    AuthenticationError,
    GoogleBackend,
    LocalBaseBackend,
    MicrosoftBackend,
    ShibbolethEdugainBackend,
    ShibbolethHakaBackend,
    ShibbolethLocalBackend,
    SuomiFiBackend,
    auth_login,
)
from base.connectors.email import send_verification_email
from base.connectors.sms import SmsConnector
from base.forms import (
    InviteTokenForm,
    LoginEmailPhoneForm,
    LoginEmailPhoneVerificationForm,
    LoginForm,
    RegistrationEmailAddressVerificationForm,
    RegistrationForm,
    RegistrationPhoneNumberForm,
    RegistrationPhoneNumberVerificationForm,
)
from base.models import TimeLimitError, Token
from base.utils import AuditLog
from identity.models import EmailAddress, Identity, PhoneNumber
from role.utils import (
    claim_membership,
    get_expiring_memberships,
    get_invitation_session_parameters,
    get_memberships_requiring_approval,
)

audit_log = AuditLog()
logger = logging.getLogger(__name__)
UserModel = get_user_model()


class InviteView(FormView):
    """
    View to check invite token and select registration process.
    """

    form_class = InviteTokenForm
    template_name = "invite.html"
    success_url = "#"

    def get_form_kwargs(self) -> dict[str, Any]:
        """
        Add initial token to the form kwargs.
        """
        kwargs = super().get_form_kwargs()
        kwargs["token"] = self.request.GET.get("token", None)
        return kwargs

    def form_valid(self, form: InviteTokenForm) -> HttpResponse:
        """
        Set invitation code to session and forward to either login or registration process.
        """
        code = form.cleaned_data["code"]
        self.request.session["invitation_code"] = code
        self.request.session["invitation_code_time"] = timezone.now().isoformat()
        if "register" in form.data:
            return HttpResponseRedirect(reverse("login-register"))
        if "login" in form.data:
            return HttpResponseRedirect(reverse("login"))
        return super().form_valid(form)


class BaseRegistrationView(View):
    """
    Base class for registration views.
    """

    template_name = "register.html"

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponseBase:
        """
        Check that user has an invitation code in session and is not already logged in.
        """
        if not self.request.user.is_anonymous:
            messages.add_message(self.request, messages.INFO, _("You are already logged in."))
            return redirect("front-page")
        # checks session parameters and raises PermissionDenied in case of problems
        get_invitation_session_parameters(request)
        return super().dispatch(request, *args, **kwargs)

    def _create_email_verification_token(self, email_address: str) -> bool:
        """
        Create and send a verification token.
        """
        try:
            token = Token.objects.create_email_address_verification_token(email_address)
        except TimeLimitError:
            messages.add_message(
                self.request, messages.WARNING, _("Tried to send a new code too soon. Please try again in one minute.")
            )
            return False
        if send_verification_email(token, email_address=email_address, lang=get_language()):
            messages.add_message(self.request, messages.INFO, _("Verification code sent."))
            return True
        else:
            messages.add_message(self.request, messages.ERROR, _("Failed to send verification code."))
            return False

    def _create_phone_verification_token(self, phone_number: str) -> bool:
        """
        Create and send a verification token.
        """
        try:
            token = Token.objects.create_phone_number_verification_token(phone_number)
        except TimeLimitError:
            messages.add_message(
                self.request, messages.WARNING, _("Tried to send a new code too soon. Please try again in one minute.")
            )
            return False
        sms_connector = SmsConnector()
        success = sms_connector.send_sms(phone_number, _("Kamu verification code: %(token)s") % {"token": token})
        if success:
            messages.add_message(self.request, messages.INFO, _("Verification code sent."))
            return True
        else:
            messages.add_message(self.request, messages.ERROR, _("Could not send an SMS message."))
            return False


class RegistrationView(BaseRegistrationView, FormView):
    """
    Registration view. Start Email and SMS registration process or forward to external methods.
    """

    template_name = "register.html"
    form_class = RegistrationForm

    def form_valid(self, form: RegistrationForm) -> HttpResponse:
        """
        Create and send a code when loading a page.
        """
        email_address = form.cleaned_data["email_address"]
        given_names = form.cleaned_data["given_names"]
        surname = form.cleaned_data["surname"]
        if not self._create_email_verification_token(email_address):
            return redirect("login-register")
        self.request.session["register_email_address"] = email_address
        self.request.session["register_given_names"] = given_names
        self.request.session["register_surname"] = surname
        return redirect("login-register-email-verify")


class RegistrationEmailAddressVerificationView(BaseRegistrationView, FormView):
    """
    Registration view for verifying email address.
    """

    template_name = "register_form.html"
    form_class = RegistrationEmailAddressVerificationForm

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponseBase:
        """
        Check that user has email address in session.
        """
        if "register_email_address" not in self.request.session:
            raise PermissionDenied
        return super().dispatch(request, *args, **kwargs)

    def get_form_kwargs(self) -> dict[str, Any]:
        """
        Add email address to form kwargs.
        """
        kwargs = super().get_form_kwargs()
        kwargs["email_address"] = self.request.session["register_email_address"]
        return kwargs

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """
        Check for resend button.
        """
        if "resend_email_code" in self.request.POST:
            email_address = self.request.session["register_email_address"]
            self._create_email_verification_token(email_address)
            return redirect("login-register-email-verify")
        return super().post(request, *args, **kwargs)

    def form_valid(self, form: RegistrationEmailAddressVerificationForm) -> HttpResponse:
        """
        Create and send a code when loading a page.
        """
        self.request.session["verified_email_address"] = self.request.session["register_email_address"]
        del self.request.session["register_email_address"]
        return redirect("login-register-phone")


class RegistrationPhoneNumberView(BaseRegistrationView, FormView):
    """
    Registration view for asking a phone number.
    """

    template_name = "register_form.html"
    form_class = RegistrationPhoneNumberForm

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponseBase:
        """
        Check that user has a verified email address in session.
        """
        if "verified_email_address" not in self.request.session:
            raise PermissionDenied
        return super().dispatch(request, *args, **kwargs)

    def form_valid(self, form: RegistrationPhoneNumberForm) -> HttpResponse:
        """
        Create and send a code when loading a page.
        """
        phone_number = form.cleaned_data["phone_number"]
        if not self._create_phone_verification_token(phone_number):
            return redirect("login-register-phone")
        self.request.session["register_phone_number"] = phone_number
        return redirect("login-register-phone-verify")


class RegistrationPhoneNumberVerificationView(BaseRegistrationView, FormView):
    """
    Registration view for verifying phone number.
    """

    template_name = "register_form.html"
    form_class = RegistrationPhoneNumberVerificationForm

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponseBase:
        """
        Check that user has a verified email address, a phone number and name information in session.
        """
        for item in ["verified_email_address", "register_phone_number", "register_given_names", "register_surname"]:
            if item not in self.request.session:
                raise PermissionDenied
        return super().dispatch(request, *args, **kwargs)

    def get_form_kwargs(self) -> dict[str, Any]:
        """
        Add phone number to form kwargs.
        """
        kwargs = super().get_form_kwargs()
        kwargs["phone_number"] = self.request.session["register_phone_number"]
        return kwargs

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """
        Check for resend button.
        """
        if "resend_phone_code" in self.request.POST:
            phone_number = self.request.session["register_phone_number"]
            self._create_phone_verification_token(phone_number)
            return redirect("login-register-phone-verify")
        return super().post(request, *args, **kwargs)

    def form_valid(self, form: RegistrationPhoneNumberVerificationForm) -> HttpResponse:
        """
        Create a new user identity with the linked user. Set basic information from the registration forms.
        """
        given_names = self.request.session["register_given_names"]
        surname = self.request.session["register_surname"]
        email_address = self.request.session["verified_email_address"]
        phone_number = self.request.session["register_phone_number"]
        identity = Identity.objects.create(
            given_names=given_names, surname=surname, assurance_level=1, preferred_language=get_language()
        )
        audit_log.info(
            f"Identity created.",
            category="identity",
            action="create",
            outcome="success",
            request=self.request,
            objects=[identity],
        )
        identity_suffix = getattr(settings, "LOCAL_IDENTITY_SUFFIX", "@local_identity")
        user = UserModel.objects.create_user(
            username=f"{identity.id}{identity_suffix}",
            email=email_address,
            first_name=given_names,
            last_name=surname,
        )
        audit_log.info(
            f"Created user { user }",
            category="user",
            action="create",
            outcome="success",
            request=self.request,
            objects=[user],
        )
        identity.user = user
        identity.save()
        audit_log.info(
            f"Identity linked to user { user }",
            category="identity",
            action="link",
            outcome="success",
            request=self.request,
            objects=[identity, user],
            log_to_db=True,
        )
        email_object = EmailAddress.objects.create(address=email_address, identity=identity, verified=True)
        audit_log.info(
            f"Email address added to identity { identity }",
            category="email_address",
            action="create",
            outcome="success",
            request=self.request,
            objects=[email_object, identity],
            log_to_db=True,
        )
        phone_object = PhoneNumber.objects.create(number=phone_number, identity=identity, verified=True)
        audit_log.info(
            f"Phone number added to identity { identity }",
            category="phone_number",
            action="create",
            outcome="success",
            request=self.request,
            objects=[phone_object, identity],
            log_to_db=True,
        )
        auth_login(self.request, user, backend="base.auth.EmailSMSBackend")
        claim_membership(self.request, identity)
        del self.request.session["verified_email_address"]
        del self.request.session["register_phone_number"]
        del self.request.session["register_given_names"]
        del self.request.session["register_surname"]
        return redirect("identity-detail", pk=identity.id)


class BaseRemoteLoginView(View):
    """
    Base class for remote login views.

    Create a new user if the user does not exist yet and user has an invitation code in the session.
    Link identifier if user is logged in and link_identifier variable is in the session.

    Set backend_class to the correct class in the subclass.
    """

    backend_class: type[LocalBaseBackend] = LocalBaseBackend

    def _remove_session_parameters(self, request: HttpRequest) -> None:
        """
        Remove session parameters used in login process.
        """
        for item in ["invitation_code", "invitation_code_time", "link_identifier", "link_identifier_time"]:
            if item in request.session:
                del request.session[item]

    def _validate_link_identifier_time(self, request: HttpRequest) -> bool:
        """
        Check that link identifier has not expired.
        """
        if "link_identifier_time" not in request.session:
            raise AuthenticationError(_("Link identifier not found"))
        link_identifier_time_limit = getattr(settings, "LINK_IDENTIFIER_TIME_LIMIT", 300)
        try:
            link_identifier_time = datetime.fromisoformat(request.session["link_identifier_time"])
        except ValueError:
            raise AuthenticationError(_("Link identifier time not valid"))
        if timezone.now() - link_identifier_time > timedelta(seconds=link_identifier_time_limit):
            raise AuthenticationError(_("Link identifier expired"))
        return True

    def _authenticate(self, request: HttpRequest, backend: LocalBaseBackend) -> UserType:
        """
        Call backend function with correct parameters, based on session variables.
        """
        if "invitation_code" in request.session and "invitation_code_time" in request.session:
            audit_log.info(
                "Started registration process",
                category="registration",
                action="info",
                backend=backend,
                request=request,
            )
            user = backend.authenticate(request, create_user=True)
        elif "link_identifier" in request.session and self._validate_link_identifier_time(request):
            audit_log.info(
                "Started identifier linking process",
                category="identifier",
                action="info",
                backend=backend,
                request=request,
            )
            user = backend.authenticate(request, link_identifier=True)
        else:
            audit_log.info(
                "Started login process",
                category="authentication",
                action="info",
                backend=backend,
                request=request,
            )
            user = backend.authenticate(request, create_user=False)
        return user

    def _authenticate_backend(self, request: HttpRequest) -> UserType:
        """
        Authentication user against a backend.
        # backend = ShibbolethBackend()
        # user = backend.authenticate(request, create_user=True)
        # return user
        """
        return self._authenticate(request, self.backend_class())

    def _remote_auth_login(self, request: HttpRequest, user: UserType) -> None:
        """
        Log user in using a correct backend.

        # auth_login(request, user, backend="base.auth.ShibbolethBackend")
        """
        backend = f"{self.backend_class.__module__}.{self.backend_class.__name__}"
        auth_login(request, user, backend=backend)
        self.request.session["external_login_backends"] = (
            self.request.session.get("external_login_backends", "") + backend + ";"
        )

    def _handle_error(self, request: HttpRequest, error: Exception) -> str:
        """
        Add error messages, remove session parameters and return redirection url to correct page.
        """
        if "link_identifier" in request.session:
            self._remove_session_parameters(request)
            messages.error(request, _("Identifier linking failed: ") + str(error))
            logger.debug("Identifier linking failed: " + str(error))
            if request.user and request.user.is_authenticated and hasattr(request.user, "identity"):
                return reverse("identity-identifier", kwargs={"pk": request.user.identity.id})
        if "invitation_code" in request.session:
            self._remove_session_parameters(request)
            messages.error(request, _("Invitation claiming failed: ") + str(error))
            logger.debug("Invitation claiming failed: " + str(error))
            return reverse("front-page")
        messages.error(request, _("Login failed: ") + str(error))
        logger.debug("Login failed: " + str(error))
        return reverse("login")

    def get(self, request: HttpRequest) -> HttpResponse:
        redirect_to = request.GET.get("next", settings.LOGIN_REDIRECT_URL)
        try:
            user = self._authenticate_backend(request)
        except AuthenticationError as e:
            return HttpResponseRedirect(self._handle_error(request, e))
        if not user.is_active:
            info_message = _("This account is inactive.")
            logger.warning(f"User {user} with inactive account tried to log in")
            return render(request, "info.html", {"message": info_message})
        if redirect_to == request.path:
            error_message = _("Redirection loop for authenticated user detected. Please contact service admins.")
            logger.error(
                "Redirection loop detected in user authentication. Check that your LOGIN_REDIRECT_URL doesn't "
                "point to the login page."
            )
            return render(request, "error.html", {"message": error_message})
        self._remote_auth_login(request, user)
        if (
            user.is_authenticated
            and "invitation_code" in request.session
            and "invitation_code_time" in request.session
        ):
            return HttpResponseRedirect(reverse("membership-claim"))
        return HttpResponseRedirect(redirect_to)


class LoginShibbolethLocalView(BaseRemoteLoginView):
    """
    LoginView to authenticate user with local Shibboleth.
    Create user if it does not exist yet.
    """

    backend_class = ShibbolethLocalBackend

    def _authenticate_backend(self, request: HttpRequest) -> UserType:
        """
        Shibboleth Local does not require invitation code to create a new user.
        """
        backend = self.backend_class()
        if "link_identifier" in request.session and self._validate_link_identifier_time(request):
            audit_log.info(
                "Started local identifier linking process",
                category="identifier",
                action="info",
                backend=backend,
                request=request,
            )
            user = backend.authenticate(request, link_identifier=True)
        else:
            audit_log.info(
                "Started local login process",
                category="authentication",
                action="info",
                backend=backend,
                request=request,
            )
            user = backend.authenticate(request, create_user=True)
        return user


class LoginShibbolethEdugainView(BaseRemoteLoginView):
    """
    LoginView to authenticate user with eduGAIN Shibboleth.
    """

    backend_class = ShibbolethEdugainBackend


class LoginShibbolethHakaView(BaseRemoteLoginView):
    """
    LoginView to authenticate user with Haka Shibboleth.
    """

    backend_class = ShibbolethHakaBackend


class LoginSuomiFiView(BaseRemoteLoginView):
    """
    LoginView to authenticate user with Suomi.fi and eIDAS.
    """

    backend_class = SuomiFiBackend


class LoginGoogleView(BaseRemoteLoginView):
    """
    LoginView to authenticate user with Google.
    """

    backend_class = GoogleBackend


class LoginMicrosoftView(BaseRemoteLoginView):
    """
    LoginView to authenticate user with Microsoft.
    """

    backend_class = MicrosoftBackend


class LoginEmailPhoneView(FormView):
    """
    View to ask email address and phone number for login.
    """

    form_class = LoginEmailPhoneForm
    template_name = "login_email.html"

    def form_valid(self, form: LoginEmailPhoneForm) -> HttpResponse:
        """
        Set session variables and redirect to verification form.
        """
        email_address = form.cleaned_data["email_address"]
        phone_number = form.cleaned_data["phone_number"]
        self.request.session["login_email_address"] = email_address
        self.request.session["login_phone_number"] = phone_number
        response = redirect("login-email-verify")
        if self.request.GET.get("next", None):
            response["Location"] += "?next=" + self.request.GET.get("next", "/")
        return response


class LoginEmailPhoneVerificationView(LoginView):
    """
    LoginView to with email address and phone number verification.
    """

    form_class = LoginEmailPhoneVerificationForm
    template_name = "login_email_verify.html"

    @method_decorator(sensitive_post_parameters())
    @method_decorator(csrf_protect)
    @method_decorator(never_cache)
    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponseBase:
        """
        Check that user has email address and phone number in session.
        """
        if "login_email_address" not in self.request.session or "login_phone_number" not in self.request.session:
            raise PermissionDenied
        return super().dispatch(request, *args, **kwargs)

    def get_form_kwargs(self) -> dict[str, Any]:
        """
        Add email address and phone_number to form kwargs.
        """
        kwargs = super().get_form_kwargs()
        kwargs["email_address"] = self.request.session["login_email_address"]
        kwargs["phone_number"] = self.request.session["login_phone_number"]
        return kwargs

    def form_valid(self, form: AuthenticationForm) -> HttpResponse:
        """
        Delete login session parameters and log user in if validation is successful.
        """
        del self.request.session["login_email_address"]
        del self.request.session["login_phone_number"]
        backend = "base.auth.EmailSMSBackend"
        auth_login(self.request, form.get_user(), backend=backend)
        return HttpResponseRedirect(self.get_success_url())

    def redirect_to_self(self) -> HttpResponse:
        response = redirect("login-email-verify")
        if self.request.GET.get("next", None):
            response["Location"] += "?next=" + self.request.GET.get("next", "/")
        return response

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """
        Check for resend button.
        """
        if "resend_email_code" in self.request.POST:
            try:
                email_address = EmailAddress.objects.get(
                    address=self.request.session["login_email_address"], verified=True
                )
            except EmailAddress.DoesNotExist:
                return self.redirect_to_self()
            except EmailAddress.MultipleObjectsReturned:
                return self.redirect_to_self()
            try:
                email_token = Token.objects.create_email_object_verification_token(email_address)
                send_verification_email(email_token, email_address.address, template="login_verification_email")
            except TimeLimitError:
                messages.add_message(
                    self.request,
                    messages.WARNING,
                    _("Tried to send a new code too soon. Please try again in one minute."),
                )
            return self.redirect_to_self()
        if "resend_phone_code" in self.request.POST:
            try:
                phone_number = PhoneNumber.objects.get(
                    number=self.request.session["login_phone_number"], verified=True
                )
            except PhoneNumber.DoesNotExist:
                return self.redirect_to_self()
            except PhoneNumber.MultipleObjectsReturned:
                return self.redirect_to_self()
            try:
                phone_token = Token.objects.create_phone_object_verification_token(phone_number)
                SmsConnector().send_sms(phone_number.number, phone_token)
            except TimeLimitError:
                messages.add_message(
                    self.request,
                    messages.WARNING,
                    _("Tried to send a new code too soon. Please try again in one minute."),
                )
            return self.redirect_to_self()
        return super().post(request, *args, **kwargs)


class LocalLoginView(LoginView):
    """
    LoginView with the custom login form.
    """

    template_name = "login_local.html"
    form_class = LoginForm

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponseBase:
        """
        Check that backend is enabled.
        """
        if "django.contrib.auth.backends.ModelBackend" not in settings.AUTHENTICATION_BACKENDS:
            raise Http404
        return super().dispatch(request, *args, **kwargs)

    def form_valid(self, form: AuthenticationForm) -> HttpResponse:
        """Security check complete. Log the user in."""
        backend = "django.contrib.auth.backends.ModelBackend"
        auth_login(self.request, form.get_user(), backend=backend)
        return HttpResponseRedirect(self.get_success_url())


class CustomLoginView(View):
    """
    View with login options
    """

    template_name = "login.html"

    def get(self, request: HttpRequest) -> HttpResponse:
        return render(request, self.template_name)


class FrontPageView(View):
    """
    Front page view.
    """

    template_name = "front.html"

    def get(self, request: HttpRequest) -> HttpResponse:
        if request.user.is_authenticated and request.user.has_perm("role.search_roles"):
            if get_memberships_requiring_approval(request.user).exists():
                link = " | <a href='" + reverse("membership-approval") + "'>" + _("List here") + "</a>"
                messages.add_message(
                    request, messages.INFO, _("You have pending membership approvals." + link), extra_tags="safe"
                )
            if get_expiring_memberships(request.user).exists():
                link = " | <a href='" + reverse("membership-expiring") + "'>" + _("List here") + "</a>"
                messages.add_message(
                    request,
                    messages.INFO,
                    _("Memberships are ending soon in roles you have approval rights.") + link,
                    extra_tags="safe",
                )
        return render(request, self.template_name)


class LocalLogoutView(LogoutView):
    """
    Custom logout view to redirect to the correct page.
    """

    def _get_backend_logout_url(self) -> str | None:
        """
        Return logout url based on the backend.
        """
        oidc_return_url = getattr(settings, "SERVICE_LINK_URL") + getattr(settings, "LOGOUT_REDIRECT_URL")
        saml_return_url = "?return=" + getattr(settings, "SERVICE_LINK_URL") + getattr(settings, "LOGOUT_REDIRECT_URL")
        logout_url = {
            "django.contrib.auth.backends.ModelBackend": getattr(settings, "LOGOUT_REDIRECT_URL"),
            "base.auth.ShibbolethLocalBackend": getattr(settings, "SAML_LOGOUT_LOCAL_PATH") + saml_return_url,
            "base.auth.ShibbolethEdugainBackend": getattr(settings, "SAML_LOGOUT_EDUGAIN_PATH") + saml_return_url,
            "base.auth.ShibbolethHakaBackend": getattr(settings, "SAML_LOGOUT_HAKA_PATH") + saml_return_url,
            "base.auth.SuomiFiBackend": getattr(settings, "SAML_LOGOUT_SUOMIFI_PATH") + saml_return_url,
            "base.auth.GoogleBackend": getattr(settings, "OIDC_LOGOUT_PATH") + oidc_return_url,
            "base.auth.MicrosoftBackend": getattr(settings, "OIDC_LOGOUT_PATH") + oidc_return_url,
            "base.auth.EmailSMSBackend": getattr(settings, "LOGOUT_REDIRECT_URL"),
        }
        backend = self.request.session.get("_auth_user_backend", None)
        return logout_url.get(backend, None)

    @method_decorator(csrf_protect)
    @method_decorator(never_cache)
    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """
        Set next page to the correct url.

        If it's from a Shibboleth SP front-channel notification, return it to return url.

        If user has logged in with multiple external backends, show a logout warning and set
        current authentication backend to the first external backend.
        """
        if "action" in request.GET and request.GET.get("action") == "logout" and "return" in request.GET:
            self.next_page = request.GET.get("return")
        else:
            external_backends: list[str] = list(
                filter(None, self.request.session.get("external_login_backends", "").split(";"))
            )
            if len(external_backends) > 1:
                self.request.session["_auth_user_backend"] = external_backends[0]
                del self.request.session["external_login_backends"]
                return render(request, "logout.html", {"multiple_backends": True})
            self.next_page = self._get_backend_logout_url()
        return super().dispatch(request, *args, **kwargs)
