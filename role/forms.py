from django.forms import ModelForm, Select
from django.forms.widgets import DateInput

from role.models import Membership, Role


class MembershipCreateForm(ModelForm[Membership]):
    class Meta:
        model = Membership
        fields = ["start_date", "expire_date"]
        widgets = {
            "start_date": DateInput(attrs={"type": "date"}),
            "expire_date": DateInput(attrs={"type": "date"}),
        }


class RoleCreateForm(ModelForm[Role]):
    class Meta:
        model = Role
        fields = ["name", "maximum_duration"]
