from django.forms import ModelForm
from django.forms.widgets import DateInput

from role.models import Membership, Role


class MembershipCreateForm(ModelForm[Membership]):
    class Meta:
        model = Membership
        fields = ["start_date", "expiring_date"]
        widgets = {"start_date": DateInput(attrs={"type": "date"}), "expiring_date": DateInput(attrs={"type": "date"})}


class RoleCreateForm(ModelForm[Role]):
    class Meta:
        model = Role
        fields = ["name"]
