"""
Base forms, shared between apps.
"""
from typing import Any

from crispy_forms.helper import FormHelper
from crispy_forms.layout import Submit
from django import forms
from django.contrib.auth.forms import AuthenticationForm
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.utils.translation import gettext as _

from base.auth import EmailSMSBackend
from base.models import Token
from identity.models import EmailAddress
from identity.validators import validate_phone_number
from role.models import Membership


class EmailPhoneForm(AuthenticationForm):
    """
    Custom AuthenticationForm to ask email-address and phone number instead of username and password.
    """

    email = forms.CharField(label=_("E-mail address"), max_length=320, validators=[validate_email])
    phone = forms.CharField(label=_("Phone number"), max_length=32)

    error_messages = {
        "invalid_login": _("Invalid email address or phone number."),
        "inactive": _("This account is inactive."),
    }

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """
        Crispy Forms helper to set form styles, configuration and buttons.
        """
        super(EmailPhoneForm, self).__init__(*args, **kwargs)
        self.fields.pop("username")
        self.fields.pop("password")
        self.helper = FormHelper()
        self.helper.add_input(Submit("submit", _("Login")))

    def clean(self) -> dict[str, Any]:
        email = self.cleaned_data.get("email")
        phone = self.cleaned_data.get("phone")

        if email and phone:
            backend = EmailSMSBackend()
            self.user_cache = backend.authenticate(self.request, email=email, phone=phone)
            if self.user_cache is None:
                raise self.get_invalid_login_error()
            else:
                self.confirm_login_allowed(self.user_cache)
        return self.cleaned_data


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

    code = forms.CharField(label=_("E-mail address verification code"), max_length=20)

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """
        Get email_address from form kwargs.
        Crispy Forms helper to set form styles, configuration and buttons.
        """
        self.email_address = kwargs.pop("email_address", None)
        super(EmailAddressVerificationForm, self).__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.add_input(Submit("submit", _("Verify")))

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

    code = forms.CharField(label=_("Phone number verification code"), max_length=20)

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """
        Get phone_number from form kwargs.
        Crispy Forms helper to set form styles, configuration and buttons.
        """
        self.phone_number = kwargs.pop("phone_number", None)
        super(PhoneNumberVerificationForm, self).__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.add_input(Submit("submit", _("Verify")))

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
