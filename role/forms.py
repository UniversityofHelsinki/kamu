"""
Role app forms.
"""

from crispy_forms.helper import FormHelper
from crispy_forms.layout import Submit
from django import forms
from django.core.exceptions import ValidationError
from django.forms.widgets import DateInput
from django.utils.translation import gettext as _

from role.models import Membership, Role, validate_membership


class TextSearchForm(forms.Form):
    """
    Form for text search.

    Using GET method to get a bookmarkable URL.
    Only use with insensitive fields as search values are set to URL parameters.
    """

    search = forms.CharField(label="search", max_length=255)

    def __init__(self, *args, **kwargs) -> None:
        """
        Crispy Forms helper to set form styles, configuration and buttons.
        """
        super(TextSearchForm, self).__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.form_class = "row row-cols-lg-auto g-3 align-items-center"
        self.helper.form_show_labels = False
        self.helper.form_method = "GET"
        self.helper.add_input(Submit("submit", _("Search")))


class MembershipCreateForm(forms.ModelForm[Membership]):
    """
    Form for creating a new membership.
    """

    def __init__(self, *args, **kwargs):
        """
        Get role from kwargs for form validation and set Crispy Forms helper.
        """
        self.role = kwargs.pop("role")
        super(MembershipCreateForm, self).__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.add_input(Submit("submit", _("Submit")))

    class Meta:
        model = Membership
        fields = ["start_date", "expire_date", "reason"]
        widgets = {
            "start_date": DateInput(attrs={"type": "date"}),
            "expire_date": DateInput(attrs={"type": "date"}),
        }

    def clean(self):
        """
        Validate dates and duration.
        """
        cleaned_data = super().clean()
        if cleaned_data is None:
            cleaned_data = self.cleaned_data
        start_date = cleaned_data.get("start_date")
        expire_date = cleaned_data.get("expire_date")
        validate_membership(ValidationError, self.role, start_date, expire_date)
