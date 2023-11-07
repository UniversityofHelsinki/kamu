import datetime

from crispy_forms.helper import FormHelper
from crispy_forms.layout import Submit
from django import forms
from django.core.exceptions import ValidationError
from django.forms.widgets import DateInput
from django.utils.translation import gettext as _

from role.models import Membership, Role


class TextSearchForm(forms.Form):
    search = forms.CharField(label="search", max_length=255)

    def __init__(self, *args, **kwargs) -> None:
        """
        Set Crispy Forms helper
        """
        super(TextSearchForm, self).__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.form_class = "row row-cols-lg-auto g-3 align-items-center"
        self.helper.form_show_labels = False
        self.helper.form_method = "GET"
        self.helper.add_input(Submit("submit", _("Search")))


class MembershipCreateForm(forms.ModelForm[Membership]):
    def __init__(self, *args, **kwargs):
        """
        Get maximum_duration from kwargs for form validation and set Crispy Forms helper
        """
        self.maximum_duration = kwargs.pop("maximum_duration")
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
        cleaned_data = super().clean()
        if cleaned_data is None:
            cleaned_data = self.cleaned_data
        start_date = cleaned_data.get("start_date")
        expire_date = cleaned_data.get("expire_date")
        if type(start_date) is not datetime.date or type(expire_date) is not datetime.date:
            raise ValidationError(_("Incorrect date format"))
        if start_date > expire_date:
            raise ValidationError(_("Start date cannot be later than expire date"))
        if (expire_date - start_date).days > self.maximum_duration:
            raise ValidationError(_("Role duration cannot be more than maximum duration"))


class RoleCreateForm(forms.ModelForm[Role]):
    def __init__(self, *args, **kwargs):
        """
        Set Crispy Forms helper
        """
        super().__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.add_input(Submit(_("submit"), "Submit"))

    class Meta:
        model = Role
        fields = [
            "identifier",
            "name_en",
            "name_fi",
            "name_sv",
            "description_en",
            "description_fi",
            "description_sv",
            "inviters",
            "approvers",
            "parent",
            "owner",
            "organisation_unit",
            "permissions",
            "iam_group",
            "maximum_duration",
        ]
