from typing import Any

from crispy_forms.helper import FormHelper
from crispy_forms.layout import Submit
from django import forms
from django.conf import settings
from django.contrib.auth.password_validation import (
    get_password_validators,
    validate_password,
)
from django.utils.translation import gettext as _


class AccountBaseForm(forms.Form):
    """
    Base form for account forms, with password and confirm password fields.
    """

    password = forms.CharField(label=_("Password"), max_length=255, widget=forms.PasswordInput)
    confirm_password = forms.CharField(label=_("Confirm password"), max_length=255, widget=forms.PasswordInput)

    def clean_password(self) -> str:
        """
        Validate password.
        """
        password = self.cleaned_data["password"]
        validate_password(password, password_validators=get_password_validators(settings.ACCOUNT_PASSWORD_VALIDATORS))
        return password

    def clean(self) -> dict[str, Any]:
        """
        Validate confirm password.
        """
        password = self.cleaned_data.get("password")
        confirm_password = self.cleaned_data.get("confirm_password")
        if password and confirm_password and password != confirm_password:
            raise forms.ValidationError(_("Passwords do not match"))
        return self.cleaned_data


class AccountCreateForm(AccountBaseForm):
    """
    Form for creating a account.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """
        Crispy Forms helper to set form styles, configuration and buttons.
        """
        super().__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.add_input(Submit("submit", _("Create account")))


class PasswordResetForm(AccountBaseForm):
    """
    Form for resetting a password.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """
        Crispy Forms helper to set form styles, configuration and buttons.
        """
        super().__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.add_input(Submit("submit", _("Reset password")))
