"""
Django admin site configuration for the account model.
"""

from kamu.admin.customization import AuditModelAdmin


class AccountAdmin(AuditModelAdmin):
    list_display = ["uid", "type", "status"]
    search_fields = [
        "identity__given_names",
        "identity__surname",
        "identity__given_name_display",
        "identity__surname_display",
        "identity__user__username",
        "uid",
    ]
    autocomplete_fields = ["identity"]
    readonly_fields = ["created_at", "updated_at"]
