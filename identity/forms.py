"""
Identity app forms.
"""

from crispy_forms.helper import FormHelper
from crispy_forms.layout import Submit
from django import forms
from django.utils.translation import gettext as _


class IdentitySearchForm(forms.Form):
    """
    Form to search identities.

    Using GET method to get a bookmarkable URL.
    Only use with insensitive fields as search values are set to URL parameters.
    """

    first_name = forms.CharField(label=_("First name"), max_length=255, required=False)
    last_name = forms.CharField(label=_("Last name"), max_length=255, required=False)
    email = forms.CharField(label=_("E-mail address"), max_length=255, required=False)

    def __init__(self, *args, **kwargs) -> None:
        """
        Crispy Forms helper to set form styles, configuration and buttons.
        """
        super(IdentitySearchForm, self).__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.form_method = "GET"
        self.helper.add_input(Submit("submit", _("Search")))
