"""
Django admin site configuration for the role models.
"""

from kamu.admin.customization import AuditModelAdmin


class PermissionAdmin(AuditModelAdmin):
    list_display = ["name", "cost"]
    search_fields = ["identifier", "name_en", "name_fi", "name_sv"]
    filter_horizontal = ("requirements",)


class RequirementAdmin(AuditModelAdmin):
    list_display = ["name", "type", "value"]
    search_fields = ["name_en", "name_fi", "name_sv", "type"]


class RoleAdmin(AuditModelAdmin):
    list_display = ["name", "parent", "owner"]
    search_fields = ["identifier", "name_en", "name_fi", "name_sv"]
    autocomplete_fields = ["parent", "owner", "organisation"]
    filter_horizontal = (
        "approvers",
        "inviters",
        "permissions",
        "requirements",
    )
