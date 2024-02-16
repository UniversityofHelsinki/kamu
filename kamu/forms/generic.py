"""
Generic forms, shared between apps.
"""

from typing import Any

from crispy_forms.helper import FormHelper
from crispy_forms.layout import Submit
from django import forms
from django.utils.translation import gettext as _


class TextSearchForm(forms.Form):
    """
    Form for text search.

    Using GET method to get a bookmarkable URL.
    Only use with insensitive fields as search values are set to URL parameters.
    """

    search = forms.CharField(label="search", max_length=255)

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """
        Crispy Forms helper to set form styles, configuration and buttons.
        """
        super().__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.form_class = "row row-cols-lg-auto g-3 align-items-center"
        self.helper.form_show_labels = False
        self.helper.form_method = "GET"
        self.helper.add_input(Submit("submit", _("Search")))
