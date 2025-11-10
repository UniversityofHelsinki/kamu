"""
Role forms.
"""

from typing import Any

from crispy_forms.helper import FormHelper
from crispy_forms.layout import Submit
from django import forms
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.forms.widgets import DateInput
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from kamu.models.membership import Membership
from kamu.validators.identity import validate_fpic, validate_phone_number
from kamu.validators.membership import validate_membership


class MembershipCreateForm(forms.ModelForm[Membership]):
    """
    Form for creating a new membership.
    """

    notify_approvers = forms.BooleanField(
        label=_("Notify approvers"),
        required=False,
        initial=True,
        help_text=_("Send notification to the role notification address about the new invite requiring approval."),
    )

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """
        Get role from kwargs for form validation and set Crispy Forms helper.
        """
        self.role = kwargs.pop("role")
        self.is_approver = kwargs.pop("is_approver", False)
        super().__init__(*args, **kwargs)
        if self.is_approver:
            del self.fields["notify_approvers"]
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
        Remove verify_phone_number field if membership is already linked to identity.
        """
        self.membership = kwargs.pop("membership")
        super().__init__(*args, **kwargs)
        if self.membership.start_date <= timezone.now().date():
            self.fields["start_date"].disabled = True
        if self.membership.identity:
            del self.fields["verify_phone_number"]
        elif self.membership.role.require_sms_verification:
            self.fields["verify_phone_number"].required = True
        self.helper = FormHelper()
        self.helper.add_input(Submit("submit", _("Update membership")))

    class Meta:
        model = Membership
        fields = ["start_date", "expire_date", "verify_phone_number", "reason"]
        widgets = {
            "start_date": DateInput(attrs={"type": "date"}, format="%Y-%m-%d"),
            "expire_date": DateInput(attrs={"type": "date"}, format="%Y-%m-%d"),
        }

    def clean_verify_phone_number(self) -> str | None:
        """
        Require verification phone number if the role requires it.
        """
        verify_phone_number = self.cleaned_data["verify_phone_number"]
        if verify_phone_number:
            validate_phone_number(verify_phone_number)
        elif self.instance.role.require_sms_verification:
            raise ValidationError(_("Verification phone number is required for this role."))
        return verify_phone_number

    def clean(self) -> None:
        """
        Validate dates and duration.
        """
        cleaned_data = super().clean()
        if cleaned_data is None:
            cleaned_data = self.cleaned_data
        start_date = cleaned_data.get("start_date")
        expire_date = cleaned_data.get("expire_date")
        validate_membership(
            ValidationError,
            self.instance.role,
            start_date,
            expire_date,
            edit=True,
            old_start_date=self.membership.start_date,
        )


class MembershipEmailCreateForm(forms.ModelForm[Membership]):
    """
    Form for creating a new membership with email invite.
    """

    notify_approvers = forms.BooleanField(
        label=_("Notify approvers"),
        required=False,
        help_text=_("Send notification to the role notification address about the new invite requiring approval."),
    )

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """
        Get role from kwargs for form validation and set Crispy Forms helper.

        Add disabled invite email address field with address from kwargs.
        """
        self.role = kwargs.pop("role")
        self.invite_email_address = kwargs.pop("email")
        self.is_approver = kwargs.pop("is_approver", False)
        super().__init__(*args, **kwargs)
        if self.is_approver:
            del self.fields["notify_approvers"]
        if self.invite_email_address:
            self.fields["invite_email_address"].initial = self.invite_email_address
            self.fields["invite_email_address"].disabled = True
        if self.role.require_sms_verification:
            self.fields["verify_phone_number"].required = True
        self.helper = FormHelper()
        self.helper.add_input(Submit("submit", _("Invite")))
        self.helper.add_input(Submit("preview_message", _("Preview message"), css_class="btn-info"))

    class Meta:
        model = Membership
        fields = [
            "invite_email_address",
            "verify_phone_number",
            "start_date",
            "expire_date",
            "reason",
            "invite_language",
            "invite_text",
        ]
        widgets = {
            "start_date": DateInput(attrs={"type": "date"}, format="%Y-%m-%d"),
            "expire_date": DateInput(attrs={"type": "date"}, format="%Y-%m-%d"),
        }

    def clean_verify_phone_number(self) -> str | None:
        """
        Require verification phone number if the role requires it.
        """
        verify_phone_number = self.cleaned_data["verify_phone_number"]
        if verify_phone_number:
            validate_phone_number(verify_phone_number)
        elif self.role.require_sms_verification:
            raise ValidationError(_("Verification phone number is required for this role."))
        return verify_phone_number

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
        if (
            Membership.objects.filter(
                role=self.role,
                identity=None,
                start_date__lte=expire_date,
                expire_date__gte=start_date,
                invite_email_address=invite_email_address,
            )
            .exclude(status=Membership.Status.CANCELLED)
            .exists()
        ):
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
    notify_approvers = forms.BooleanField(
        label=_("Notify approvers"),
        required=False,
        help_text=_("Send notification to the role notification address about the new invite requiring approval."),
    )

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """
        Get role and invite_limit from kwargs for form validation and set Crispy Forms helper.

        Add preview message button.
        """
        self.role = kwargs.pop("role")
        self.invite_limit = kwargs.pop("invite_limit")
        self.is_approver = kwargs.pop("is_approver", False)
        super().__init__(*args, **kwargs)
        if self.is_approver:
            del self.fields["notify_approvers"]
        self.helper = FormHelper()
        self.helper.add_input(Submit("submit", _("Invite")))
        self.helper.add_input(Submit("preview_message", _("Preview message"), css_class="btn-info"))

    class Meta:
        model = Membership
        fields = ["start_date", "expire_date", "reason", "invite_language", "invite_text"]
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
