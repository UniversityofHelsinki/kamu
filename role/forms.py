import datetime

from django.core.exceptions import ValidationError
from django.forms import ModelForm
from django.forms.widgets import DateInput
from django.utils.translation import gettext as _

from role.models import Membership, Role


class MembershipCreateForm(ModelForm[Membership]):
    def __init__(self, *args, **kwargs):
        """
        Get maximum_duration from kwargs for form validation
        """
        self.maximum_duration = kwargs.pop("maximum_duration")
        super(MembershipCreateForm, self).__init__(*args, **kwargs)

    class Meta:
        model = Membership
        fields = ["start_date", "expire_date"]
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


class RoleCreateForm(ModelForm[Role]):
    class Meta:
        model = Role
        fields = ["name", "maximum_duration"]
