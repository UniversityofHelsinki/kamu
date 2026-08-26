"""
Django admin site configuration for the identity models.
"""

from typing import Any

from django import forms
from django.contrib.auth.admin import GroupAdmin, UserAdmin
from django.contrib.auth.models import Group, User
from django.http import HttpRequest
from rest_framework.authtoken.admin import TokenAdmin

from kamu.admin.customization import AuditModelAdmin


class GroupCreationForm(forms.ModelForm[Group]):
    """
    A form that creates a group, with no privileges.
    """

    class Meta:
        model = Group
        fields = ("name",)


class AuditUserAdmin(AuditModelAdmin, UserAdmin[User]):
    """
    Customized class for Django UserAdmin that adds Kamu auditing.
    """

    readonly_fields = ["date_joined", "last_login"]


class AuditGroupAdmin(AuditModelAdmin, GroupAdmin):
    """
    Customized class for Django GroupAdmin that adds Kamu auditing.
    """

    add_form = GroupCreationForm

    def get_form(
        self, request: HttpRequest, obj: Any | None = None, change: bool = False, **kwargs: Any
    ) -> type[forms.ModelForm[Group]]:
        """
        Use special form during user creation
        """
        defaults = {}
        if obj is None:
            defaults["form"] = self.add_form
        defaults.update(kwargs)
        return super().get_form(request, obj, change, **defaults)


class AuditTokenAdmin(AuditModelAdmin, TokenAdmin):
    """
    Customized TokenAdmin to limit displaying token and adding Kamu auditing.
    """

    raw_id_fields = ["user"]
    list_display = ["user", "created"]
