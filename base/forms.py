"""
Base forms, shared between apps.
"""

from crispy_forms.helper import FormHelper
from crispy_forms.layout import Submit
from django import forms
from django.contrib.auth.forms import AuthenticationForm
from django.core.validators import validate_email
from django.utils.translation import gettext as _

from base.auth import EmailSMSBackend


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

    def __init__(self, request=None, *args, **kwargs) -> None:
        """
        Crispy Forms helper to set form styles, configuration and buttons.
        """
        super(EmailPhoneForm, self).__init__(*args, **kwargs)
        self.fields.pop("username")
        self.fields.pop("password")
        self.helper = FormHelper()
        self.helper.add_input(Submit("submit", _("Login")))

    def clean(self):
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


class LoginForm(AuthenticationForm):
    """
    Custom AuthenticationForm to add crispy forms helper.
    """

    def __init__(self, *args, **kwargs) -> None:
        """
        Crispy Forms helper to set form styles, configuration and buttons.
        """
        super(LoginForm, self).__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.add_input(Submit("submit", _("Login")))
