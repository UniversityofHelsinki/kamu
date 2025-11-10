"""
Auth forms
"""

from typing import Any

from crispy_forms.helper import FormHelper
from crispy_forms.layout import Submit
from django import forms
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.models import User as UserType
from django.core.exceptions import (
    MultipleObjectsReturned,
    ObjectDoesNotExist,
    ValidationError,
)
from django.core.validators import validate_email
from django.http import HttpRequest
from django.utils.translation import gettext_lazy as _

from kamu.backends import AuthenticationError, EmailSMSBackend
from kamu.connectors import ApiError
from kamu.connectors.email import send_verification_email
from kamu.connectors.sms import SmsConnector
from kamu.models.identity import EmailAddress, PhoneNumber
from kamu.models.membership import Membership
from kamu.models.token import TimeLimitError, Token
from kamu.validators.identity import validate_phone_number


class LoginEmailPhoneForm(forms.Form):
    """
    Form for email and SMS login.
    """

    email_address = forms.CharField(label=_("Email address"), max_length=320, validators=[validate_email])
    phone_number = forms.CharField(
        label=_("Phone number"),
        max_length=32,
        help_text=_("Phone number in international format, e.g. +358123456789."),
    )

    error_messages = {
        "invalid_login": _("Invalid email address or phone number."),
        "inactive": _("This account is inactive."),
    }

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """
        Crispy Forms helper to set form styles, configuration and buttons.
        """
        super().__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.add_input(Submit("submit", _("Login")))

    def clean_phone_number(self) -> str:
        phone_number = self.cleaned_data["phone_number"]
        number = phone_number.replace(" ", "")
        validate_phone_number(number)
        return number

    def clean(self) -> dict[str, Any]:
        """
        Validate that there is only one verified instance of email address and phone number, and
        they are for the same identity.

        Create and send verification tokens if possible.
        """
        email_address = self.cleaned_data.get("email_address")
        phone_number = self.cleaned_data.get("phone_number")
        try:
            email_obj = EmailAddress.objects.get(address=email_address, verified__isnull=False)
            phone_obj = PhoneNumber.objects.get(number=phone_number, verified__isnull=False)
        except (MultipleObjectsReturned, ObjectDoesNotExist):
            raise ValidationError(_("This contact information cannot be used to login."))
        if email_obj.identity.user and email_obj.identity.user == phone_obj.identity.user:
            try:
                email_token = Token.objects.create_email_object_verification_token(email_obj)
                phone_token = Token.objects.create_phone_object_verification_token(phone_obj)
                send_verification_email(email_token, email_obj.address, template="login_verification_email")
                SmsConnector().send_sms(phone_obj.number, phone_token)
            except TimeLimitError:
                raise ValidationError(_("Tried to send new login tokens too soon. Please try again in one minute."))
            except ApiError:
                raise ValidationError(_("Could not send SMS, please try again later."))
            return self.cleaned_data
        raise ValidationError(_("Invalid email address or phone number."))


class LoginEmailPhoneVerificationForm(AuthenticationForm):
    """
    Form for email and SMS login verification.
    """

    email_verification_token = forms.CharField(label=_("Email verification code"), max_length=32, required=False)
    phone_verification_token = forms.CharField(label=_("SMS verification code"), max_length=32, required=False)

    def __init__(self, request: HttpRequest | None = None, *args: Any, **kwargs: Any) -> None:
        """
        Crispy Forms helper to set form styles, configuration and buttons.
        """
        self.user_cache: Any = None
        self.email_address = kwargs.pop("email_address", None)
        self.phone_number = kwargs.pop("phone_number", None)
        super().__init__(*args, **kwargs)
        self.request = request
        self.fields.pop("username")
        self.fields.pop("password")
        self.fields["email_verification_token"].widget.attrs.update(autocomplete="off")
        self.fields["phone_verification_token"].widget.attrs.update(autocomplete="off")
        self.helper = FormHelper()
        self.helper.add_input(Submit("submit", _("Verify")))
        self.helper.add_input(Submit("resend_email_code", _("Resend email code"), css_class="btn-warning"))
        self.helper.add_input(Submit("resend_phone_code", _("Resend phone code"), css_class="btn-warning"))

    def clean_email_verification_token(self) -> str:
        """
        Check that there is only one verified email address and that token is valid for that address.
        """
        token = self.cleaned_data["email_verification_token"]
        if not token or len(token) < 4:
            raise ValidationError(_("Invalid verification code."))
        try:
            email_address = EmailAddress.objects.get(address=self.email_address, verified__isnull=False)
        except EmailAddress.DoesNotExist:
            raise ValidationError(_("This email address cannot be used to login."))
        except EmailAddress.MultipleObjectsReturned:
            raise ValidationError(_("This email address cannot be used to login."))
        if not Token.objects.validate_email_object_verification_token(token, email_address, remove_token=False):
            raise ValidationError(_("Invalid verification code."))
        return token

    def clean_phone_verification_token(self) -> str:
        """
        Check that there is only one verified phone number and that token is valid for that number.
        """
        token = self.cleaned_data["phone_verification_token"]
        if not token or len(token) < 4:
            raise ValidationError(_("Invalid verification code."))
        try:
            phone_number = PhoneNumber.objects.get(number=self.phone_number, verified__isnull=False)
        except PhoneNumber.DoesNotExist:
            raise ValidationError(_("This phone number cannot be used to login."))
        except PhoneNumber.MultipleObjectsReturned:
            raise ValidationError(_("This phone number cannot be used to login."))
        if not Token.objects.validate_phone_object_verification_token(token, phone_number, remove_token=False):
            raise ValidationError(_("Invalid verification code."))
        return token

    def clean(self) -> dict[str, Any]:
        """
        Call authentication backend if all required attributes are given.
        """
        email_token = self.cleaned_data.get("email_verification_token")
        phone_token = self.cleaned_data.get("phone_verification_token")
        if not self.email_address or not self.phone_number:
            raise ValidationError(_("Error when logging in, please try again."))
        backend = EmailSMSBackend()
        try:
            self.user_cache = backend.authenticate(
                self.request,
                email_address=self.email_address,
                email_token=email_token,
                phone_number=self.phone_number,
                phone_token=phone_token,
            )
        except AuthenticationError:
            raise ValidationError(_("Error when logging in, please try again."))
        if self.user_cache is None:
            raise ValidationError(_("Error when logging in, please try again."))
        if not self.user_cache.is_active:
            raise ValidationError(_("This account is disabled."))
        return self.cleaned_data

    def get_user(self) -> UserType:
        return self.user_cache


class RegistrationForm(forms.Form):
    """
    First form in email and SMS registration process
    """

    given_names = forms.CharField(
        max_length=200, label=_("Given names"), required=False, help_text=_("All official given names.")
    )
    surname = forms.CharField(label=_("Surname"), max_length=200, required=False, help_text=_("Official surname(s)."))
    email_address = forms.CharField(label=_("Email address"), max_length=320, validators=[validate_email])

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """
        Crispy Forms helper to set form styles, configuration and buttons.
        """
        self.membership = kwargs.pop("membership")
        super().__init__(*args, **kwargs)
        if self.membership.invite_email_address:
            self.fields["email_address"].initial = self.membership.invite_email_address
            self.fields["email_address"].disabled = True
            self.fields["email_address"].help_text = _("This email address is already set by the inviter.")
        self.helper = FormHelper()
        self.helper.add_input(Submit("submit", _("Send verification code")))

    def clean_email_address(self) -> str:
        """
        Test if email address is already in use.
        """
        email_address = self.cleaned_data["email_address"]
        if EmailAddress.objects.filter(address=email_address, verified__isnull=False).exists():
            raise ValidationError(_("This email address is already linked to an account."))
        return email_address

    def clean(self) -> dict[str, Any]:
        """
        Test that either given_names or surname is filled in.
        """
        cleaned_data = super().clean()
        if not cleaned_data:
            raise ValidationError(_("Invalid form data."))
        given_names = cleaned_data.get("given_names")
        surname = cleaned_data.get("surname")
        if not given_names and not surname:
            raise ValidationError(_("Either given names or surname must be filled in."))
        return cleaned_data


class RegistrationEmailAddressVerificationForm(forms.Form):
    """
    Email address verification form for login process
    """

    code = forms.CharField(label=_("Enter the verification code you received by email"), max_length=20, required=False)

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """
        Get email_address from form kwargs.
        Crispy Forms helper to set form styles, configuration and buttons.
        """
        self.email_address = kwargs.pop("email_address", None)
        super().__init__(*args, **kwargs)
        self.fields["code"].widget.attrs.update(autocomplete="off")
        self.helper = FormHelper()
        self.helper.add_input(Submit("submit", _("Verify email address")))
        self.helper.add_input(Submit("resend_email_code", _("Send new code"), css_class="btn-warning"))

    def clean_code(self) -> str:
        """
        Test verification code.
        """
        code = self.cleaned_data["code"]
        if (
            not code
            or len(code) < 4
            or not Token.objects.validate_email_address_verification_token(code, self.email_address)
        ):
            raise ValidationError(
                _(
                    "Invalid verification code. Please note that the verification code is different from the "
                    "invitation code. If you have received more than one verification code, only the most recent one "
                    "will be valid."
                )
            )
        return code


class RegistrationPhoneNumberForm(forms.Form):
    """
    Phone number form
    """

    phone_number = forms.CharField(
        label=_("Enter your phone number for SMS verification"),
        max_length=20,
        help_text=_(
            "Enter the phone number in the international format, e.g. +358123456789. Please note that we will not "
            "forward the phone number."
        ),
    )

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """
        Crispy Forms helper to set form styles, configuration and buttons.
        """
        self.membership = kwargs.pop("membership")
        super().__init__(*args, **kwargs)
        if self.membership.verify_phone_number:
            self.fields["phone_number"].initial = self.membership.verify_phone_number
            self.fields["phone_number"].disabled = True
            self.fields["phone_number"].help_text = _("This phone number is already set by the inviter.")

        self.helper = FormHelper()
        self.helper.add_input(Submit("submit", _("Send verification code by SMS")))

    def clean_phone_number(self) -> str:
        phone_number = self.cleaned_data["phone_number"]
        number = phone_number.replace(" ", "")
        validate_phone_number(number)
        return number


class RegistrationPhoneNumberVerificationForm(forms.Form):
    """
    Phone number verification form for login process
    """

    code = forms.CharField(label=_("Enter the verification code you received by SMS"), max_length=20, required=False)

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """
        Get phone_number from form kwargs.
        Crispy Forms helper to set form styles, configuration and buttons.
        """
        self.phone_number = kwargs.pop("phone_number", None)
        super().__init__(*args, **kwargs)
        self.fields["code"].widget.attrs.update(autocomplete="off")
        self.helper = FormHelper()
        self.helper.add_input(Submit("submit", _("Verify phone number")))
        self.helper.add_input(Submit("resend_phone_code", _("Send new code"), css_class="btn-warning"))

    def clean_code(self) -> str:
        """
        Test verification code.
        """
        code = self.cleaned_data["code"]
        if (
            not code
            or len(code) < 4
            or not Token.objects.validate_phone_number_verification_token(code, self.phone_number)
        ):
            raise ValidationError(
                _(
                    "Invalid verification code. If you sent yourself more than one verification code, "
                    "only the most recent one will be valid."
                )
            )
        return code


class LoginForm(AuthenticationForm):
    """
    Custom AuthenticationForm to add crispy forms helper.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """
        Crispy Forms helper to set form styles, configuration and buttons.
        """
        super().__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.add_input(Submit("submit", _("Login")))

    def clean(self) -> dict[str, Any]:
        username = self.cleaned_data.get("username")
        password = self.cleaned_data.get("password")
        if username is not None and password:
            backend = ModelBackend()
            self.user_cache = backend.authenticate(self.request, username=username, password=password)
            if self.user_cache is None:
                raise self.get_invalid_login_error()
            else:
                self.confirm_login_allowed(self.user_cache)
        return self.cleaned_data


class InviteTokenForm(forms.Form):
    """
    Form to check an invitation token.
    """

    code = forms.CharField(label=_("Personal invitation code"), max_length=320, required=True)

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """
        Fill initial token if given.
        Crispy Forms helper to set submit button.
        """
        token = kwargs.pop("token", None)
        super().__init__(*args, **kwargs)
        if token:
            self.fields["code"].initial = token
        self.fields["code"].widget.attrs.update(autocomplete="off")
        self.helper = FormHelper()
        self.helper.form_tag = False

    def clean_code(self) -> str:
        """
        Test the invite code.
        Check for existing membership and a valid token.
        """
        code = self.cleaned_data["code"]
        parts = code.split(":")
        if len(parts) != 2:
            raise forms.ValidationError(_("Invalid invitation code."))
        membership_pk = parts[0]
        token = parts[1]
        try:
            membership_pk = int(membership_pk)
        except ValueError:
            raise forms.ValidationError(_("Invalid invitation code."))
        try:
            membership = Membership.objects.get(pk=membership_pk)
        except Membership.DoesNotExist:
            raise forms.ValidationError(_("Invalid invitation code."))
        if not Token.objects.validate_invite_token(token, membership=membership, remove_token=False):
            raise forms.ValidationError(_("Invalid invitation code."))
        return code
