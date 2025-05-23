"""
Role forms.
"""

from typing import Any

from crispy_forms.helper import FormHelper
from crispy_forms.layout import Submit
from django import forms
from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.forms.widgets import DateInput
from django.utils.translation import gettext_lazy as _
from django_stubs_ext import StrPromise

from kamu.models.membership import Membership
from kamu.validators.identity import validate_fpic, validate_phone_number
from kamu.validators.membership import validate_membership


class MembershipCreateForm(forms.ModelForm[Membership]):
    """
    Form for creating a new membership.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """
        Get role from kwargs for form validation and set Crispy Forms helper.
        """
        self.role = kwargs.pop("role")
        super().__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.add_input(Submit("submit", _("Add member")))

    class Meta:
        model = Membership
        fields = ["start_date", "expire_date", "reason"]
        widgets = {
            "start_date": DateInput(attrs={"type": "date"}, format="%Y-%m-%d"),
            "expire_date": DateInput(attrs={"type": "date"}, format="%Y-%m-%d"),
        }

    def clean(self) -> None:
        """
        Validate dates and duration.
        """
        cleaned_data = super().clean()
        if cleaned_data is None:
            cleaned_data = self.cleaned_data
        start_date = cleaned_data.get("start_date")
        expire_date = cleaned_data.get("expire_date")
        validate_membership(ValidationError, self.role, start_date, expire_date)


class MembershipEditForm(forms.ModelForm[Membership]):
    """
    Form for editing membership.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """
        Get role from kwargs for form validation and set Crispy Forms helper.
        """
        super().__init__(*args, **kwargs)
        self.fields["start_date"].disabled = True
        self.helper = FormHelper()
        self.helper.add_input(Submit("submit", _("Update")))

    class Meta:
        model = Membership
        fields = ["start_date", "expire_date", "reason"]
        widgets = {
            "start_date": DateInput(attrs={"type": "date"}, format="%Y-%m-%d"),
            "expire_date": DateInput(attrs={"type": "date"}, format="%Y-%m-%d"),
        }

    def clean(self) -> None:
        """
        Validate dates and duration.
        """
        cleaned_data = super().clean()
        if cleaned_data is None:
            cleaned_data = self.cleaned_data
        start_date = cleaned_data.get("start_date")
        expire_date = cleaned_data.get("expire_date")
        validate_membership(ValidationError, self.instance.role, start_date, expire_date, edit=True)


help_text_invite_text: StrPromise = _(
    "This replaces beginning of the default invite message. Lines of the invite text are wrapped to 70 "
    "characters. Invite code and link will be added to end of the message. Use preview to see the final "
    "result."
)


class MembershipEmailCreateForm(forms.ModelForm[Membership]):
    """
    Form for creating a new membership with email invite.
    """

    invite_language = forms.ChoiceField(label=_("Invite language"), choices=settings.LANGUAGES)
    invite_text = forms.CharField(
        label=_("Invite text"), widget=forms.Textarea, required=False, help_text=help_text_invite_text
    )

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """
        Get role from kwargs for form validation and set Crispy Forms helper.

        Add disabled invite email address field with address from kwargs.
        """
        self.role = kwargs.pop("role")
        self.invite_email_address = kwargs.pop("email")
        super().__init__(*args, **kwargs)
        if self.invite_email_address:
            self.fields["invite_email_address"].initial = self.invite_email_address
            self.fields["invite_email_address"].disabled = True
        self.helper = FormHelper()
        self.helper.add_input(Submit("submit", _("Invite")))
        self.helper.add_input(Submit("preview_message", _("Preview message"), css_class="btn-info"))

    class Meta:
        model = Membership
        fields = ["invite_email_address", "start_date", "expire_date", "reason"]
        widgets = {
            "start_date": DateInput(attrs={"type": "date"}, format="%Y-%m-%d"),
            "expire_date": DateInput(attrs={"type": "date"}, format="%Y-%m-%d"),
        }

    def clean(self) -> None:
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
            raise ValidationError(_("This email address already has an invite to the role during this time period."))


class MembershipMassCreateForm(forms.ModelForm[Membership]):
    """
    Form for creating multiple new memberships.
    """

    invited = forms.CharField(
        label=_("Invited persons"),
        widget=forms.Textarea,
        help_text=_(
            "Invited persons, one per line. Each line should contain email address, followed by optional phone "
            "number and/or Finnish personal identity code, values separated by comma. Phone number must be in "
            'international format. Example: "person@example.org,+358501234567,010181-900C"'
        ),
    )
    invite_language = forms.ChoiceField(label=_("Invite language"), choices=settings.LANGUAGES)
    invite_text = forms.CharField(
        label=_("Invite text"), widget=forms.Textarea, required=False, help_text=help_text_invite_text
    )

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """
        Get role and invite_limit from kwargs for form validation and set Crispy Forms helper.

        Add preview message button.
        """
        self.role = kwargs.pop("role")
        self.invite_limit = kwargs.pop("invite_limit")
        super().__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.add_input(Submit("submit", _("Invite")))
        self.helper.add_input(Submit("preview_message", _("Preview message"), css_class="btn-info"))

    class Meta:
        model = Membership
        fields = ["start_date", "expire_date", "reason"]
        widgets = {
            "start_date": DateInput(attrs={"type": "date"}, format="%Y-%m-%d"),
            "expire_date": DateInput(attrs={"type": "date"}, format="%Y-%m-%d"),
        }

    def _parse_value(self, value: str) -> dict[str, str]:
        """
        Parse value and return dictionary with email, phone or fpic key.

        Raises ValidationError if value is not valid.
        """
        try:
            validate_email(value)
            return {"email": value}
        except ValidationError:
            pass
        try:
            validate_phone_number(value)
            return {"phone": value}
        except ValidationError:
            pass
        validate_fpic(value)
        return {"fpic": value}

    def clean_invited(self) -> list[dict[str, str]]:
        """
        Validate invited persons and parse values to dictionary.
        """
        data = self.cleaned_data.get("invited")
        if not data:
            raise ValidationError(_("No invited persons."))
        lines = data.splitlines()
        if len(lines) > self.invite_limit:
            raise ValidationError(_("Too many invited persons."))
        invited = []
        for line in lines:
            person = {}
            parts = line.split(",")
            for part in parts:
                if not part.strip():
                    continue
                try:
                    value = self._parse_value(part.strip())
                except ValidationError:
                    raise ValidationError(_("Invalid value: %(part)s"), params={"part": part})
                person.update(value)
            if not person:
                raise ValidationError(_("Invalid line: %(line)s"), params={"line": line})
            invited.append(person)
        return invited

    def clean(self) -> None:
        """
        Validate membership dates and duration.
        """
        cleaned_data = super().clean()
        if cleaned_data is None:
            cleaned_data = self.cleaned_data
        start_date = cleaned_data.get("start_date")
        expire_date = cleaned_data.get("expire_date")
        validate_membership(ValidationError, self.role, start_date, expire_date)
