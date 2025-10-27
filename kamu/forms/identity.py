"""
Identity forms.
"""

from typing import Any

from crispy_forms.bootstrap import FormActions
from crispy_forms.helper import FormHelper
from crispy_forms.layout import HTML, Div, Layout, Submit
from django import forms
from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.urls import reverse
from django.utils.translation import gettext_lazy as _

from kamu.models.identity import (
    Country,
    EmailAddress,
    Identity,
    Nationality,
    PhoneNumber,
)
from kamu.models.token import Token
from kamu.validators.identity import validate_fpic, validate_phone_number


class IdentityCombineForm(forms.Form):
    """
    Form for combining two identities.
    """

    primary_identity = forms.IntegerField(label=_("Target primary key"))
    secondary_identity = forms.IntegerField(label=_("Source primary key"))

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """
        Crispy Forms helper to set form styles, configuration and buttons.
        """
        super().__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.add_input(Submit("combine", _("Combine")))


class IdentitySearchForm(forms.Form):
    """
    Form to search identities.
    """

    given_names = forms.CharField(label=_("Given name(s)"), max_length=255, required=False)
    surname = forms.CharField(label=_("Surname"), max_length=255, required=False)
    uid = forms.CharField(label=_("User account"), max_length=255, required=False)
    email = forms.CharField(label=_("Email address"), max_length=255, required=False)
    phone = forms.CharField(
        label=_("Phone number"),
        max_length=20,
        required=False,
        help_text=_("Use international format, e.g. +358401234567, including only numbers and + sign."),
    )
    fpic = forms.CharField(label=_("Finnish personal identity code"), max_length=11, required=False)

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """
        Crispy Forms helper to set form styles, configuration and buttons.
        """
        use_ldap = kwargs.pop("use_ldap", False)
        super().__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.form_method = "POST"
        self.helper.add_input(Submit("submit", _("Search"), css_class="me-2"))
        self.helper.add_input(Submit("reset_form", _("Reset"), css_class="btn-warning"))

        if use_ldap:
            name_search_text = _(
                "Name search returns partial matches from Kamu and names starting with the search parameters "
                "in the user directory."
            )
        else:
            name_search_text = _("Name search returns partial matches from Kamu.")
        self.helper.layout = Layout(
            HTML("<h2 class='mb-3'>" + _("Name search") + "</h2>"),
            HTML("<p>" + name_search_text + "</p>"),
            Div(
                Div("given_names", css_class="col-md-6"),
                Div("surname", css_class="col-md-6"),
                css_class="row mb-3",
            ),
            HTML("<h2 class='mb-3'>" + _("Identifiers") + "</h2>"),
            HTML(
                "<p>"
                + _(
                    "Identifier search matches only exact identifiers. Each identifier is searched separately "
                    "and the results are added to the final search results."
                )
                + "</p>"
            ),
            Div(
                Div("uid", css_class="col-md-6"),
                Div("email", css_class="col-md-6"),
                Div("phone", css_class="col-md-6"),
                Div("fpic", css_class="col-md-6"),
                css_class="row mb-3",
            ),
        )

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

    def clean_fpic(self) -> str | None:
        """
        Only allow valid personal codes in search field.
        """
        fpic = self.cleaned_data["fpic"]
        if not fpic:
            return None
        validate_fpic(fpic)
        return fpic


class ContactForm(forms.Form):
    """
    Create or update contact addresses
    """

    contact = forms.CharField(
        label=_("Email address or phone number"),
        help_text=_(
            "Phone number in international format, e.g. +358123456789. Values containing @ are treated as email "
            "addresses."
        ),
        max_length=320,
        required=False,
    )

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """
        Crispy Forms helper to set submit button.
        """
        self.identity = kwargs.pop("identity")
        super().__init__(*args, **kwargs)
        self.helper = FormHelper()
        layout = Layout(
            Div("contact"),
            FormActions(
                Submit("submit", _("Add")),
                HTML(
                    '<a class="btn btn-secondary ms-2" href="'
                    + reverse("identity-detail", kwargs={"pk": self.identity.pk})
                    + '">'
                    + _("Return")
                    + "</a>"
                ),
            ),
        )
        self.helper.add_layout(layout)

    def clean_contact(self) -> str:
        """
        Check that contact address exists and is an email address or phone number.
        Check for contact limits.
        Add contact_type to form data.
        """
        contact = self.cleaned_data["contact"]
        if not contact:
            raise ValidationError(_("Email address or phone number is required."))
        contact_limit = getattr(settings, "CONTACT_LIMIT", 3)
        if "@" in contact:
            validate_email(contact)
            self.cleaned_data["contact_type"] = "email"
            if EmailAddress.objects.filter(identity=self.identity, address=contact).exists():
                raise ValidationError(_("Email address already exists."))
            if EmailAddress.objects.filter(identity=self.identity).count() >= contact_limit:
                raise ValidationError(_("Maximum number of email addresses reached."))
        else:
            contact = contact.replace(" ", "")
            validate_phone_number(contact)
            self.cleaned_data["contact_type"] = "phone"
            if PhoneNumber.objects.filter(identity=self.identity, number=contact).exists():
                raise ValidationError(_("Phone number already exists."))
            if PhoneNumber.objects.filter(identity=self.identity).count() >= contact_limit:
                raise ValidationError(_("Maximum number of phone numbers reached."))
        return contact


class EmailAddressVerificationForm(forms.ModelForm):
    """
    Verify an email address
    """

    code = forms.CharField(label=_("Email verification code"), max_length=32, required=False)

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """
        Crispy Forms helper to set submit and resend buttons.
        """
        super().__init__(*args, **kwargs)
        self.fields["address"].disabled = True
        self.fields["code"].widget.attrs.update(autocomplete="off")
        self.helper = FormHelper()
        self.helper.add_input(Submit("submit", _("Save")))
        self.helper.add_input(Submit("resend_code", _("Resend a code")))

    def clean_code(self) -> str:
        """
        Test verification code.
        """
        code = self.cleaned_data["code"]
        if not code:
            raise ValidationError(_("Invalid verification code."))
        if not Token.objects.validate_email_object_verification_token(code, self.instance):
            raise ValidationError(_("Invalid verification code."))
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

    code = forms.CharField(label=_("SMS verification code"), max_length=32, required=False)

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """
        Crispy Forms helper to set submit and resend buttons.
        """
        super().__init__(*args, **kwargs)
        self.fields["number"].disabled = True
        self.fields["code"].widget.attrs.update(autocomplete="off")
        self.helper = FormHelper()
        self.helper.add_input(Submit("submit", _("Save")))
        self.helper.add_input(Submit("resend_code", _("Resend a code")))

    def clean_code(self) -> str:
        """
        Test verification code.
        """
        code = self.cleaned_data["code"]
        if not code:
            raise ValidationError(_("Invalid verification code."))
        if not Token.objects.validate_phone_object_verification_token(code, self.instance):
            raise ValidationError(_("Invalid verification code."))
        return code

    class Meta:
        model = PhoneNumber
        fields = [
            "number",
        ]


class CheckboxSelectMultipleWithDisable(forms.CheckboxSelectMultiple):
    """
    CheckboxSelectMultiple widget that disables choices in disabled_choices.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self.disabled_choices = kwargs.pop("disabled_choices", [])
        super().__init__(*args, **kwargs)

    def create_option(self, name: str, value: Any, *args: Any, **kwargs: Any) -> dict[str, Any]:
        option = super().create_option(name, value, *args, **kwargs)
        option["attrs"]["disabled"] = value in self.disabled_choices
        return option


class IdentityForm(forms.ModelForm):
    """
    Create or update user identity
    """

    add_nationality = forms.ModelChoiceField(
        label=_("Add nationality"), queryset=Country.objects.all(), required=False
    )
    add_nationality_verification = forms.ChoiceField(
        label=_("Nationality verification method"),
        choices=Identity.VerificationMethod.choices,
        initial=Identity.VerificationMethod.UNVERIFIED,
        required=False,
    )
    remove_nationality = forms.ModelMultipleChoiceField(
        label=_("Remove nationality"),
        queryset=Nationality.objects.none(),
        required=False,
        widget=CheckboxSelectMultipleWithDisable,
    )

    def _create_layout(self, include_restricted_fields: bool, include_verification_fields: bool) -> Layout:
        """
        Create layout for IdentityForm.
        """
        layout = Layout(
            HTML("<h2 class='mb-3'>" + _("Basic information") + "</h2>"),
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
                    HTML("<h2 class='mb-3 mt-5'>" + _("Restricted information") + "</h2>"),
                    Div(
                        Div("date_of_birth", css_class="col-md-8"),
                        css_class="row mb-3",
                    ),
                    Div(
                        Div("gender", css_class="col-md-8"),
                        css_class="row mb-3",
                    ),
                    Div(
                        Div("fpic", css_class="col-md-8"),
                        css_class="row mb-3",
                    ),
                    Div(
                        Div("add_nationality", css_class="col-md-8"),
                        css_class="row mb-3",
                    ),
                    Div(
                        Div("remove_nationality", css_class="col-md-8"),
                        css_class="row mb-3",
                    ),
                ]
            )
            if include_verification_fields:
                layout[7].append(Div("date_of_birth_verification", css_class="col-md-4"))
                layout[8].append(Div("gender_verification", css_class="col-md-4"))
                layout[9].append(Div("fpic_verification", css_class="col-md-4"))
                layout[10].append(Div("add_nationality_verification", css_class="col-md-4"))
            layout.append(
                FormActions(
                    Submit("submit", _("Save changes")),
                    HTML(
                        '<a class="btn btn-secondary ms-2" href="'
                        + reverse("identity-detail", kwargs={"pk": self.instance.pk})
                        + '">'
                        + _("Return")
                        + "</a>"
                    ),
                )
            )
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
        if hasattr(self.fields["add_nationality"], "queryset"):
            self.fields["add_nationality"].queryset = Country.objects.order_by(*Country.get_ordering_by_name())
        if hasattr(self.fields["remove_nationality"], "queryset"):
            self.fields["remove_nationality"].queryset = Nationality.objects.filter(identity=self.instance)
        self.helper = FormHelper()
        restricted_fields = True
        verification_fields = True
        self.fields["gender"].required = False
        # Remove choice for strong electrical verification as it cannot be set manually.
        # Ignore type checking as choices is not defined in base Field class.
        self.fields["add_nationality_verification"].choices = [  # type: ignore[attr-defined]
            choice
            for choice in self.fields["add_nationality_verification"].choices  # type: ignore[attr-defined]
            if choice[0] < Identity.VerificationMethod.STRONG
        ]
        for field in self.instance.basic_verification_fields() + self.instance.restricted_verification_fields():
            if self.initial and self.initial[field] < Identity.VerificationMethod.STRONG:
                self.fields[field].choices = [  # type: ignore[attr-defined]
                    choice
                    for choice in self.fields[field].choices  # type: ignore[attr-defined]
                    if choice[0] < Identity.VerificationMethod.STRONG
                ]
        if not self.instance or self.instance.user == self.request.user:
            # Do not show verification fields when user is modifying their own information.
            # Disable fields that are already strongly verified.
            verification_fields = False
            disable_verify_level = getattr(
                settings, "ATTRIBUTE_VERIFICATION_LEVEL_UNEDITABLE", Identity.VerificationMethod.PHOTO_ID
            )
            for field in self.instance.basic_verification_fields() + self.instance.restricted_verification_fields():
                if self.initial and self.initial[field] >= disable_verify_level:
                    self.fields[field.removesuffix("_verification")].disabled = True
                del self.fields[field]
            if "remove_nationality" in self.fields:
                self.fields["remove_nationality"].widget.disabled_choices = Nationality.objects.filter(
                    identity=self.instance, verification_method__gte=disable_verify_level
                ).values_list("pk", flat=True)
        elif not self.request.user.has_perms(["kamu.change_restricted_information"]):
            # Remove restricted fields if user does not have permission to modify them.
            restricted_fields = False
            for field in self.instance.restricted_fields() + self.instance.restricted_verification_fields():
                del self.fields[field]
        self.helper.layout = self._create_layout(restricted_fields, verification_fields)

    def clean_remove_nationality(self) -> Any:
        """
        Prevent removing verified nationalities if current user.
        """
        remove_nationalities = self.cleaned_data["remove_nationality"]
        if self.instance and self.instance.user == self.request.user:
            disable_verify_level = getattr(
                settings, "ATTRIBUTE_VERIFICATION_LEVEL_UNEDITABLE", Identity.VerificationMethod.PHOTO_ID
            )
            for nationality in remove_nationalities:
                if nationality.verification_method >= disable_verify_level:
                    raise ValidationError(_("Cannot remove verified nationality."))
        return remove_nationalities

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
            verification = cleaned_data.get(f"{field}_verification")
            initial_verification = initial_data.get(f"{field}_verification")
            if (
                value != initial_value
                or (initial_verification is not None and initial_verification < Identity.VerificationMethod.STRONG)
            ) and verification == Identity.VerificationMethod.STRONG:
                self.add_error(f"{field}_verification", _("Cannot set strong electrical verification manually."))

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
            "gender_verification",
            "fpic",
            "fpic_verification",
        ]
        widgets = {
            "date_of_birth": forms.DateInput(attrs={"type": "date"}, format="%Y-%m-%d"),
        }
