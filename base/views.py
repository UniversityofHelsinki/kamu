"""
Base views, shared between apps.
"""

import logging
from typing import Any

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import get_user_model
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.models import User as UserType
from django.contrib.auth.views import LoginView
from django.core.exceptions import PermissionDenied
from django.http import (
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

from base.auth import GoogleBackend, MicrosoftBackend, ShibbolethBackend, auth_login
from base.connectors.email import send_verification_email
from base.connectors.sms import SmsConnector
from base.forms import (
    EmailAddressVerificationForm,
    EmailPhoneForm,
    EmailPhoneVerificationForm,
    InviteTokenForm,
    LoginForm,
    PhoneNumberForm,
    PhoneNumberVerificationForm,
    RegistrationForm,
)
from base.models import TimeLimitError, Token
from identity.models import EmailAddress, Identity, PhoneNumber
from role.utils import claim_membership, get_invitation_session_parameters

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
        kwargs = super(InviteView, self).get_form_kwargs()
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
            return HttpResponseRedirect(reverse("login") + "?next=" + reverse("membership-claim"))
        return super().form_valid(form)


class BaseRegisterView(View):
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


class RegisterView(BaseRegisterView, FormView):
    """
    Registration view. Start Email and SMS registration process or forward to external methods.
    """

    template_name = "register.html"
    form_class = RegistrationForm

    def _create_verification_token(self, email_address: str) -> bool:
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

    def form_valid(self, form: RegistrationForm) -> HttpResponse:
        """
        Create and send a code when loading a page.
        """
        email_address = form.cleaned_data["email_address"]
        given_names = form.cleaned_data["given_names"]
        surname = form.cleaned_data["surname"]
        if not self._create_verification_token(email_address):
            return redirect("login-register")
        self.request.session["register_email_address"] = email_address
        self.request.session["register_given_names"] = given_names
        self.request.session["register_surname"] = surname
        return redirect("login-register-email-verify")


class VerifyEmailAddressView(BaseRegisterView, FormView):
    """
    Registration view for verifying email address.
    """

    template_name = "register_form.html"
    form_class = EmailAddressVerificationForm

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
        kwargs = super(VerifyEmailAddressView, self).get_form_kwargs()
        kwargs["email_address"] = self.request.session["register_email_address"]
        return kwargs

    def form_valid(self, form: EmailAddressVerificationForm) -> HttpResponse:
        """
        Create and send a code when loading a page.
        """
        self.request.session["verified_email_address"] = self.request.session["register_email_address"]
        del self.request.session["register_email_address"]
        return redirect("login-register-phone")


class RegisterPhoneNumberView(BaseRegisterView, FormView):
    """
    Registration view for asking a phone number.
    """

    template_name = "register_form.html"
    form_class = PhoneNumberForm

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponseBase:
        """
        Check that user has a verified email address in session.
        """
        if "verified_email_address" not in self.request.session:
            raise PermissionDenied
        return super().dispatch(request, *args, **kwargs)

    def _create_verification_token(self, phone_number: str) -> bool:
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

    def form_valid(self, form: PhoneNumberForm) -> HttpResponse:
        """
        Create and send a code when loading a page.
        """
        phone_number = form.cleaned_data["phone_number"]
        if not self._create_verification_token(phone_number):
            return redirect("login-register-phone")
        self.request.session["register_phone_number"] = phone_number
        return redirect("login-register-phone-verify")


class VerifyPhoneNumberView(BaseRegisterView, FormView):
    """
    Registration view for verifying phone number.
    """

    template_name = "register_form.html"
    form_class = PhoneNumberVerificationForm

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
        kwargs = super(VerifyPhoneNumberView, self).get_form_kwargs()
        kwargs["phone_number"] = self.request.session["register_phone_number"]
        return kwargs

    def form_valid(self, form: PhoneNumberVerificationForm) -> HttpResponse:
        """
        Create a new user identity with the linked user. Set basic information from the registration forms.
        """
        given_names = self.request.session["register_given_names"]
        surname = self.request.session["register_surname"]
        email_address = self.request.session["verified_email_address"]
        phone_number = self.request.session["register_phone_number"]
        identity = Identity.objects.create(
            given_names=given_names, surname=surname, assurance_level="low", preferred_language=get_language()
        )
        identity_suffix = getattr(settings, "LOCAL_IDENTITY_SUFFIX", "@local_identity")
        user = UserModel.objects.create_user(
            username=f"{identity.id}{identity_suffix}",
            email=email_address,
            first_name=given_names,
            last_name=surname,
        )
        identity.user = user
        identity.save()
        EmailAddress.objects.create(address=email_address, identity=identity, verified=True)
        PhoneNumber.objects.create(number=phone_number, identity=identity, verified=True)
        auth_login(self.request, user, backend="base.auth.EmailSMSBackend")
        claim_membership(self.request, identity)
        del self.request.session["verified_email_address"]
        del self.request.session["register_phone_number"]
        del self.request.session["register_given_names"]
        del self.request.session["register_surname"]
        return redirect("identity-detail", pk=identity.id)


class RemoteLoginView(View):
    """
    Base class for remote login views. Overwrite _authenticate_backend and _auth_login methods with
    correct backend settings.
    """

    @staticmethod
    def _authenticate_backend(request: HttpRequest) -> None | UserType:
        """
        Authentication user against a backend.
        # backend = ShibbolethBackend()
        # user = backend.authenticate(request, create_user=True)
        # return user
        """
        return None

    @staticmethod
    def _remote_auth_login(request: HttpRequest, user: UserType) -> None:
        """
        Log user in using a correct backend.

        # auth_login(request, user, backend="base.auth.ShibbolethBackend")
        """
        pass

    def get(self, request: HttpRequest) -> HttpResponse:
        redirect_to = request.GET.get("next", settings.LOGIN_REDIRECT_URL)
        user = self._authenticate_backend(request)
        if user:
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
            return HttpResponseRedirect(redirect_to)
        else:
            messages.error(request, _("Login failed."))
            logger.debug("Failed login")
        return HttpResponseRedirect(reverse("login"))


class ShibbolethLoginView(RemoteLoginView):
    """
    LoginView to authenticate user with Shibboleth
    """

    @staticmethod
    def _authenticate_backend(request: HttpRequest) -> UserType | None:
        backend = ShibbolethBackend()
        user = backend.authenticate(request, create_user=True)
        return user

    @staticmethod
    def _remote_auth_login(request: HttpRequest, user: UserType) -> None:
        auth_login(request, user, backend="base.auth.ShibbolethBackend")


class GoogleLoginView(RemoteLoginView):
    """
    LoginView to authenticate user with Google.

    Create a new user if the user does not exist yet and user has an invitation code in the session.
    """

    @staticmethod
    def _authenticate_backend(request: HttpRequest) -> UserType | None:
        backend = GoogleBackend()
        if "invitation_code" in request.session and "invitation_code_time" in request.session:
            user = backend.authenticate(request, create_user=True)
        else:
            user = backend.authenticate(request, create_user=False)
        return user

    @staticmethod
    def _remote_auth_login(request: HttpRequest, user: UserType) -> None:
        auth_login(request, user, backend="base.auth.GoogleBackend")


class MicrosoftLoginView(RemoteLoginView):
    """
    LoginView to authenticate user with Microsoft.

    Create a new user if the user does not exist yet and user has an invitation code in the session.
    """

    @staticmethod
    def _authenticate_backend(request: HttpRequest) -> UserType | None:
        backend = MicrosoftBackend()
        if "invitation_code" in request.session and "invitation_code_time" in request.session:
            user = backend.authenticate(request, create_user=True)
        else:
            user = backend.authenticate(request, create_user=False)
        return user

    @staticmethod
    def _remote_auth_login(request: HttpRequest, user: UserType) -> None:
        auth_login(request, user, backend="base.auth.MicrosoftBackend")


class EmailPhoneLoginView(FormView):
    """
    View to ask email address and phone number for login.
    """

    form_class = EmailPhoneForm
    template_name = "login_email.html"

    def form_valid(self, form: EmailPhoneForm) -> HttpResponse:
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


class EmailPhoneLoginVerificationView(LoginView):
    """
    LoginView to with email address and phone number verification.
    """

    form_class = EmailPhoneVerificationForm
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
        kwargs = super(EmailPhoneLoginVerificationView, self).get_form_kwargs()
        kwargs["email_address"] = self.request.session["login_email_address"]
        kwargs["phone_number"] = self.request.session["login_phone_number"]
        return kwargs

    def form_valid(self, form: AuthenticationForm) -> HttpResponse:
        """
        Delete login session parameters and log user in if validation is successful.
        """
        del self.request.session["login_email_address"]
        del self.request.session["login_phone_number"]
        auth_login(self.request, form.get_user(), backend="base.auth.EmailSMSBackend")
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

    def form_valid(self, form: AuthenticationForm) -> HttpResponse:
        """Security check complete. Log the user in."""
        auth_login(self.request, form.get_user(), backend="django.contrib.auth.backends.ModelBackend")
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
        return render(request, self.template_name)
