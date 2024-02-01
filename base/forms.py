"""
Base forms, shared between apps.
"""

from typing import Any

from crispy_forms.helper import FormHelper
from crispy_forms.layout import Submit
from django import forms
from django.contrib.auth.base_user import AbstractBaseUser
from django.contrib.auth.forms import AuthenticationForm
from django.core.exceptions import (
    MultipleObjectsReturned,
    ObjectDoesNotExist,
    ValidationError,
)
from django.core.validators import validate_email
from django.http import HttpRequest
from django.utils.translation import gettext as _

from base.auth import AuthenticationError, EmailSMSBackend
from base.connectors.email import send_verification_email
from base.connectors.sms import SmsConnector
from base.models import TimeLimitError, Token
from identity.models import EmailAddress, PhoneNumber
from identity.validators import validate_phone_number
from role.models import Membership


class EmailPhoneForm(forms.Form):
    """
    Form for e-mail and SMS login.
    """

    email_address = forms.CharField(label=_("E-mail address"), max_length=320, validators=[validate_email])
    phone_number = forms.CharField(label=_("Phone number"), max_length=32)

    error_messages = {
        "invalid_login": _("Invalid email address or phone number."),
        "inactive": _("This account is inactive."),
    }

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """
        Crispy Forms helper to set form styles, configuration and buttons.
        """
        super(EmailPhoneForm, self).__init__(*args, **kwargs)
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
            email_obj = EmailAddress.objects.get(address=email_address, verified=True)
            phone_obj = PhoneNumber.objects.get(number=phone_number, verified=True)
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
            return self.cleaned_data
        raise ValidationError(_("Invalid email address or phone number."))


class EmailPhoneVerificationForm(AuthenticationForm):
    """
    Form for e-mail and SMS login verification.
    """

    email_verification_token = forms.CharField(label=_("E-mail verification code"), max_length=32, required=False)
    phone_verification_token = forms.CharField(label=_("SMS verification code"), max_length=32, required=False)

    def __init__(self, request: HttpRequest | None = None, *args: Any, **kwargs: Any) -> None:
        """
        Crispy Forms helper to set form styles, configuration and buttons.
        """
        self.request = request
        self.user_cache: Any = None
        self.email_address = kwargs.pop("email_address", None)
        self.phone_number = kwargs.pop("phone_number", None)
        super(EmailPhoneVerificationForm, self).__init__(*args, **kwargs)
        self.fields.pop("username")
        self.fields.pop("password")
        self.helper = FormHelper()
        self.helper.add_input(Submit("submit", _("Verify")))
        self.helper.add_input(Submit("resend_email_code", _("Resend an email code"), css_class="btn-warning"))
        self.helper.add_input(Submit("resend_phone_code", _("Resend a phone code"), css_class="btn-warning"))

    def clean_email_verification_token(self) -> str:
        """
        Check that there is only one verified email address and that token is valid for that address.
        """
        token = self.cleaned_data["email_verification_token"]
        if not token or len(token) < 4:
            raise ValidationError(_("Invalid verification code."))
        try:
            email_address = EmailAddress.objects.get(address=self.email_address, verified=True)
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
            phone_number = PhoneNumber.objects.get(number=self.phone_number, verified=True)
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

    def get_user(self) -> AbstractBaseUser:
        return self.user_cache


class RegistrationForm(forms.Form):
    """
    First form in email and SMS registration process
    """

    given_names = forms.CharField(
        max_length=200, label=_("Given names"), required=False, help_text=_("All official first names.")
    )
    surname = forms.CharField(label=_("Surname"), max_length=200, required=False, help_text=_("Official surname(s)."))
    email_address = forms.CharField(label=_("E-mail address"), max_length=320, validators=[validate_email])

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """
        Crispy Forms helper to set form styles, configuration and buttons.
        """
        super(RegistrationForm, self).__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.add_input(Submit("submit", _("Send verification code")))

    def clean_email_address(self) -> str:
        """
        Test if email address is already in use.
        """
        email_address = self.cleaned_data["email_address"]
        if EmailAddress.objects.filter(address=email_address, verified=True).exists():
            raise ValidationError(_("This e-mail address is already linked to an account."))
        return email_address

    def clean(self) -> None:
        """
        Test that either given_names or surname is filled in.
        """
        cleaned_data = super().clean()
        if not cleaned_data:
            raise ValidationError(_("Invalid form data"))
        given_names = cleaned_data.get("given_names")
        surname = cleaned_data.get("surname")
        if not given_names and not surname:
            raise ValidationError(_("Either given names or surname must be filled in."))


class EmailAddressVerificationForm(forms.Form):
    """
    Email address verification form
    """

    code = forms.CharField(label=_("E-mail verification code"), max_length=20, required=False)

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """
        Get email_address from form kwargs.
        Crispy Forms helper to set form styles, configuration and buttons.
        """
        self.email_address = kwargs.pop("email_address", None)
        super(EmailAddressVerificationForm, self).__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.add_input(Submit("submit", _("Verify")))
        self.helper.add_input(Submit("resend_email_code", _("Resend verification code"), css_class="btn-warning"))

    def clean_code(self) -> str:
        """
        Test verification code.
        """
        code = self.cleaned_data["code"]
        if not code or len(code) < 4:
            raise ValidationError(_("Invalid verification code"))
        if not Token.objects.validate_email_address_verification_token(code, self.email_address):
            raise ValidationError(_("Invalid verification code"))
        return code


class PhoneNumberForm(forms.Form):
    """
    Phone number form
    """

    phone_number = forms.CharField(label=_("Phone number"), max_length=20)

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """
        Crispy Forms helper to set form styles, configuration and buttons.
        """
        super(PhoneNumberForm, self).__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.add_input(Submit("submit", _("Send verification code")))

    def clean_phone_number(self) -> str:
        phone_number = self.cleaned_data["phone_number"]
        number = phone_number.replace(" ", "")
        validate_phone_number(number)
        return number


class PhoneNumberVerificationForm(forms.Form):
    """
    Phone number verification form
    """

    code = forms.CharField(label=_("SMS verification code"), max_length=20, required=False)

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """
        Get phone_number from form kwargs.
        Crispy Forms helper to set form styles, configuration and buttons.
        """
        self.phone_number = kwargs.pop("phone_number", None)
        super(PhoneNumberVerificationForm, self).__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.add_input(Submit("submit", _("Verify")))
        self.helper.add_input(Submit("resend_phone_code", _("Resend verification code"), css_class="btn-warning"))

    def clean_code(self) -> str:
        """
        Test verification code.
        """
        code = self.cleaned_data["code"]
        if not code or len(code) < 4:
            raise ValidationError(_("Invalid verification code"))
        if not Token.objects.validate_phone_number_verification_token(code, self.phone_number):
            raise ValidationError(_("Invalid verification code"))
        return code


class LoginForm(AuthenticationForm):
    """
    Custom AuthenticationForm to add crispy forms helper.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """
        Crispy Forms helper to set form styles, configuration and buttons.
        """
        super(LoginForm, self).__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.add_input(Submit("submit", _("Login")))


class InviteTokenForm(forms.Form):
    """
    Form to check an invitation token.
    """

    code = forms.CharField(label=_("Invitation code"), max_length=320, required=True)

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """
        Fill initial token if given.
        Crispy Forms helper to set submit button.
        """
        token = kwargs.pop("token", None)
        super(InviteTokenForm, self).__init__(*args, **kwargs)
        if token:
            self.fields["code"].initial = token
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
            raise forms.ValidationError(_("Invalid invitation code"))
        membership_pk = parts[0]
        token = parts[1]
        try:
            membership_pk = int(membership_pk)
        except ValueError:
            raise forms.ValidationError(_("Invalid invitation code"))
        try:
            membership = Membership.objects.get(pk=membership_pk)
        except Membership.DoesNotExist:
            raise forms.ValidationError(_("Invalid invitation code"))
        if not Token.objects.validate_invite_token(token, membership=membership, remove_token=False):
            raise forms.ValidationError(_("Invalid invitation code"))
        return code
