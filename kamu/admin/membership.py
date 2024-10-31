"""
Django admin site configuration for the membership models.
"""

from kamu.admin.customization import AuditModelAdmin


class MembershipAdmin(AuditModelAdmin):
    list_display = ["identity", "role", "start_date", "expire_date"]
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
