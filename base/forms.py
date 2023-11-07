from crispy_forms.helper import FormHelper
from crispy_forms.layout import Submit
from django.contrib.auth.forms import AuthenticationForm
from django.utils.translation import gettext as _


class LoginForm(AuthenticationForm):
    def __init__(self, *args, **kwargs) -> None:
        """
        Set Crispy Forms helper
        """
        super(LoginForm, self).__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.add_input(Submit("submit", _("Login")))
