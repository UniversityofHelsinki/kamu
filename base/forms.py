"""
Base forms, shared between apps.
"""

from crispy_forms.helper import FormHelper
from crispy_forms.layout import Submit
from django.contrib.auth.forms import AuthenticationForm
from django.utils.translation import gettext as _


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
