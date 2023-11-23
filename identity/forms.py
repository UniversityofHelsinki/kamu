"""
Identity app forms.
"""

from crispy_forms.helper import FormHelper
from crispy_forms.layout import HTML, Div, Layout, Submit
from django import forms
from django.core.exceptions import ValidationError
from django.utils.translation import gettext as _

from identity.models import Identity


class IdentitySearchForm(forms.Form):
    """
    Form to search identities.

    Using GET method to get a bookmarkable URL.
    Only use with insensitive fields as search values are set to URL parameters.
    """

    given_names = forms.CharField(label=_("Given name(s)"), max_length=255, required=False)
    surname = forms.CharField(label=_("Surname"), max_length=255, required=False)
    email = forms.CharField(label=_("E-mail address"), max_length=255, required=False)

    def __init__(self, *args, **kwargs) -> None:
        """
        Crispy Forms helper to set form styles, configuration and buttons.
        """
        super(IdentitySearchForm, self).__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.form_method = "GET"
        self.helper.add_input(Submit("submit", _("Search")))


class IdentityForm(forms.ModelForm):
    """
    Create or update user identity
    """

    @staticmethod
    def _create_layout(include_restricted_fields, include_verification_fields) -> Layout:
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

    def __init__(self, *args, **kwargs):
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
        self.helper.add_input(Submit(_("submit"), "Save"))
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

    def clean(self):
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
