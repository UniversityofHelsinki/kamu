"""
Identity app forms.
"""

from typing import Any

from crispy_forms.helper import FormHelper
from crispy_forms.layout import HTML, Div, Layout, Submit
from django import forms
from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.utils.translation import gettext as _

from base.models import Token
from identity.models import EmailAddress, Identity, PhoneNumber
from identity.validators import validate_phone_number


class IdentitySearchForm(forms.Form):
    """
    Form to search identities.

    Using GET method to get a bookmarkable URL.
    Only use with insensitive fields as search values are set to URL parameters.
    """

    given_names = forms.CharField(label=_("Given name(s)"), max_length=255, required=False)
    surname = forms.CharField(label=_("Surname"), max_length=255, required=False)
    email = forms.CharField(label=_("E-mail address"), max_length=255, required=False)
    phone = forms.CharField(label=_("Phone number"), max_length=20, required=False)

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """
        Crispy Forms helper to set form styles, configuration and buttons.
        """
        super(IdentitySearchForm, self).__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.form_method = "GET"
        self.helper.add_input(Submit("submit", _("Search")))

    def clean_phone(self) -> str | None:
        """
        Only allow valid phone numbers in search field.
        """
        phone = self.cleaned_data["phone"]
        if not phone:
            return None
        phone = phone.strip().replace(" ", "")
        validate_phone_number(phone)
        return phone

    def clean_email(self) -> str | None:
        """
        Only allow valid emails in search field.
        """
        email = self.cleaned_data["email"]
        if not email:
            return None
        validate_email(email)
        return email


class ContactForm(forms.Form):
    """
    Create or update contact addresses
    """

    contact = forms.CharField(label=_("E-mail address or phone number"), max_length=320, required=False)

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """
        Crispy Forms helper to set submit button.
        """
        self.identity = kwargs.pop("identity")
        super(ContactForm, self).__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.add_input(Submit("submit", _("Add")))

    def clean_contact(self) -> str:
        """
        Check that contact address exists and is an email address or phone number.
        Check for contact limits.
        Add contact_type to form data.
        """
        contact = self.cleaned_data["contact"]
        email = True
        phone = True
        if not contact:
            raise ValidationError(_("E-mail address or phone number is required"))
        try:
            validate_email(contact)
        except ValidationError:
            email = False
        try:
            contact = contact.replace(" ", "")
            validate_phone_number(contact)
        except ValidationError:
            phone = False
        if not email and not phone:
            raise ValidationError(_("Invalid e-mail address or phone number"))
        contact_limit = getattr(settings, "CONTACT_LIMIT", 3)
        if phone:
            self.cleaned_data["contact_type"] = "phone"
            if PhoneNumber.objects.filter(identity=self.identity, number=contact).exists():
                raise ValidationError(_("Phone number already exists"))
            if PhoneNumber.objects.filter(identity=self.identity).count() >= contact_limit:
                raise ValidationError(_("Maximum number of phone numbers reached"))
        if email:
            self.cleaned_data["contact_type"] = "email"
            if EmailAddress.objects.filter(identity=self.identity, address=contact).exists():
                raise ValidationError(_("E-mail address already exists"))
            if EmailAddress.objects.filter(identity=self.identity).count() >= contact_limit:
                raise ValidationError(_("Maximum number of e-mail addresses reached"))
        return contact


class EmailAddressVerificationForm(forms.ModelForm):
    """
    Verify an email address
    """

    code = forms.CharField(label=_("Verify code"), max_length=32, required=False)

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """
        Crispy Forms helper to set submit and resend buttons.
        """
        super(EmailAddressVerificationForm, self).__init__(*args, **kwargs)
        self.fields["address"].disabled = True
        self.helper = FormHelper()
        self.helper.add_input(Submit("submit", _("Save")))
        self.helper.add_input(Submit("resend_code", _("Resend a code")))

    def clean_code(self) -> str:
        """
        Test verification code.
        """
        code = self.cleaned_data["code"]
        if not code:
            raise ValidationError(_("Invalid verification code"))
        if not Token.objects.validate_email_object_verification_token(code, self.instance):
            raise ValidationError(_("Invalid verification code"))
        return code

    class Meta:
        model = EmailAddress
        fields = [
            "address",
        ]


class PhoneNumberVerificationForm(forms.ModelForm):
    """
    Verify a phone number
    """

    code = forms.CharField(label=_("Verify code"), max_length=32, required=False)

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """
        Crispy Forms helper to set submit and resend buttons.
        """
        super(PhoneNumberVerificationForm, self).__init__(*args, **kwargs)
        self.fields["number"].disabled = True
        self.helper = FormHelper()
        self.helper.add_input(Submit("submit", _("Save")))
        self.helper.add_input(Submit("resend_code", _("Resend a code")))

    def clean_code(self) -> str:
        """
        Test verification code.
        """
        code = self.cleaned_data["code"]
        if not code:
            raise ValidationError(_("Invalid verification code"))
        if not Token.objects.validate_phone_object_verification_token(code, self.instance):
            raise ValidationError(_("Invalid verification code"))
        return code

    class Meta:
        model = PhoneNumber
        fields = [
            "number",
        ]


class IdentityForm(forms.ModelForm):
    """
    Create or update user identity
    """

    @staticmethod
    def _create_layout(include_restricted_fields: bool, include_verification_fields: bool) -> Layout:
        """
        Create layout for IdentityForm.
        """
        layout = Layout(
            HTML(_("<h2 class='mb-3'>Basic information</h2>")),
            Div(
                Div("given_names", css_class="col-md-8"),
                css_class="row mb-3",
            ),
            Div(
                Div("surname", css_class="col-md-8"),
                css_class="row mb-3",
            ),
            Div(
                Div("given_name_display", css_class="col-md-8"),
                css_class="row mb-3",
            ),
            Div(
                Div("surname_display", css_class="col-md-8"),
                css_class="row mb-3",
            ),
            Div(
                Div("preferred_language", css_class="col-md-8"),
                css_class="row mb-3 border-bottom",
            ),
        )
        if include_verification_fields:
            layout[1].append(Div("given_names_verification", css_class="col-md-4"))
            layout[2].append(Div("surname_verification", css_class="col-md-4"))
        if include_restricted_fields:
            layout.extend(
                [
                    HTML(_("<h2 class='mb-3'>Restricted information</h2>")),
                    Div(
                        Div("date_of_birth", css_class="col-md-8"),
                        css_class="row mb-3",
                    ),
                    Div(
                        Div("gender", css_class="col-md-8"),
                        css_class="row mb-3",
                    ),
                    Div(
                        Div("nationality", css_class="col-md-8"),
                        css_class="row mb-3",
                    ),
                    Div(
                        Div("fpic", css_class="col-md-8"),
                        css_class="row mb-3",
                    ),
                ]
            )
            if include_verification_fields:
                layout[7].append(Div("date_of_birth_verification", css_class="col-md-4"))
                layout[9].append(Div("nationality_verification", css_class="col-md-4"))
                layout[10].append(Div("fpic_verification", css_class="col-md-4"))
        return layout

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """
        Restrict fields to basic information unless
        - user is modifying their own information,
        - or has permission to modify restricted information.

        Remove verification fields when user is modifying their own information.

        Crispy Forms helper to set submit button.
        """
        self.request = kwargs.pop("request")
        super().__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.add_input(Submit("submit", _("Save")))
        restricted_fields = True
        verification_fields = True
        if not self.instance or self.instance.user == self.request.user:
            verification_fields = False
            for field in self.instance.basic_verification_fields() + self.instance.restricted_verification_fields():
                if self.initial and self.initial[field] == 4:
                    self.fields[field.removesuffix("_verification")].disabled = True
                del self.fields[field]
        elif not self.request.user.has_perms(["identity.change_restricted_information"]):
            restricted_fields = False
            for field in self.instance.restricted_fields() + self.instance.restricted_verification_fields():
                del self.fields[field]
        self.helper.layout = self._create_layout(restricted_fields, verification_fields)

    def clean(self) -> None:
        """
        Check that strong electrical verification cannot be set by hand.
        """
        cleaned_data = super().clean()
        if not cleaned_data:
            return None
        initial_data = self.initial
        verifiable_fields = self.instance.verifiable_fields()
        for field in verifiable_fields:
            value = cleaned_data.get(field)
            initial_value = initial_data.get(field)
            verification = cleaned_data.get(f"{ field }_verification")
            initial_verification = initial_data.get(f"{ field }_verification")
            if (
                value != initial_value or (initial_verification is not None and initial_verification < 4)
            ) and verification == 4:
                self.add_error(f"{ field }_verification", _("Cannot set strong electrical verification by hand."))

    class Meta:
        model = Identity
        fields = [
            "given_names",
            "given_names_verification",
            "surname",
            "surname_verification",
            "given_name_display",
            "surname_display",
            "preferred_language",
            "date_of_birth",
            "date_of_birth_verification",
            "gender",
            "nationality",
            "nationality_verification",
            "fpic",
            "fpic_verification",
        ]
        widgets = {
            "date_of_birth": forms.DateInput(attrs={"type": "date"}),
        }
