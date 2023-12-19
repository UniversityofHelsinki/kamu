"""
Role app forms.
"""

from crispy_forms.helper import FormHelper
from crispy_forms.layout import Submit
from django import forms
from django.conf import settings
from django.core.exceptions import ValidationError
from django.forms.widgets import DateInput
from django.utils.translation import gettext as _

from role.models import Membership, validate_membership


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
        self.helper.add_input(Submit("submit", _("Add member")))

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


class MembershipEmailCreateForm(forms.ModelForm[Membership]):
    """
    Form for creating a new membership with email invite.
    """

    invite_language = forms.ChoiceField(label=_("Invite language"), choices=settings.LANGUAGES)

    def __init__(self, *args, **kwargs):
        """
        Get role from kwargs for form validation and set Crispy Forms helper.

        Add disabled invite email address field with address from kwargs.
        """
        self.role = kwargs.pop("role")
        self.invite_email_address = kwargs.pop("email")
        super(MembershipEmailCreateForm, self).__init__(*args, **kwargs)
        if self.invite_email_address:
            self.fields["invite_email_address"].initial = self.invite_email_address
            self.fields["invite_email_address"].disabled = True
        self.helper = FormHelper()
        self.helper.add_input(Submit("submit", _("Invite")))

    class Meta:
        model = Membership
        fields = ["invite_email_address", "start_date", "expire_date", "reason"]
        widgets = {
            "start_date": DateInput(attrs={"type": "date"}),
            "expire_date": DateInput(attrs={"type": "date"}),
        }

    def clean(self):
        """
        Validate dates, duration and overlapping memberships.
        """
        cleaned_data = super().clean()
        if cleaned_data is None:
            cleaned_data = self.cleaned_data
        start_date = cleaned_data.get("start_date")
        expire_date = cleaned_data.get("expire_date")
        invite_email_address = cleaned_data.get("invite_email_address")
        validate_membership(ValidationError, self.role, start_date, expire_date)
        if Membership.objects.filter(
            role=self.role,
            identity=None,
            start_date__lte=expire_date,
            expire_date__gte=start_date,
            invite_email_address=invite_email_address,
        ).exists():
            raise ValidationError(_("This email address has an invite during the time period."))
