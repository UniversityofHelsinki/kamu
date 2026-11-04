"""
Role forms
"""

from typing import Any

from django import forms
from django.utils.translation import gettext_lazy as _

from kamu.forms.generic import TextSearchForm
from kamu.models.role import Permission


class RoleSearchForm(TextSearchForm):
    """
    Adds permissions to the text search form for role search.

    Using GET method to get a bookmarkable URL.
    Only use with nonsensitive fields as search values are set to URL parameters.
    """

    permission = forms.ChoiceField(
        label=_("Permission"),
        choices=[],
        required=False,
        help_text=_("Service permissions apply only to limited user accounts."),
    )

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """
        Crispy Forms helper to set form styles, configuration and buttons.
        """
        super().__init__(*args, **kwargs)
        self.fields["search"].required = False
        permissions = Permission.objects.all().order_by("type", Permission.get_ordering_by_name()[0])
        grouped_choices = [
            (
                label,
                [(perm.pk, perm.name()) for perm in permissions if perm.type == value],
            )
            for value, label in Permission.Type.choices
        ]
        self.fields["permission"].choices = [("", _("All permissions"))] + [  # type: ignore[attr-defined]
            group for group in grouped_choices if group[1]
        ]
