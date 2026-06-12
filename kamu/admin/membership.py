"""
Django admin site configuration for the membership models.
"""

from typing import Any

from django.contrib import admin
from django.utils.translation import gettext_lazy as _

from kamu.admin.customization import AuditModelAdmin


@admin.action(description=_("Name or invite email"))
def name_or_invite_email(obj: Any) -> str:
    if obj.identity:
        return obj.identity.display_name()
    return obj.invite_email_address


class MembershipAdmin(AuditModelAdmin):
    list_display = [name_or_invite_email, "role", "start_date", "expire_date"]
    list_filter = ["role__identifier", ("identity", admin.EmptyFieldListFilter)]
    search_fields = [
        "identity__surname",
        "identity__given_names",
        "role__name_fi",
        "role__name_sv",
        "role__name_en",
        "approver__first_name",
        "approver__last_name",
    ]
    autocomplete_fields = ["identity", "role", "approver", "inviter"]
    readonly_fields = ["created_at", "updated_at"]
