"""
Django admin site configuration for the role models.
"""

from kamu.admin.customization import AuditModelAdmin, OrderByNameMixin


class PermissionAdmin(OrderByNameMixin, AuditModelAdmin):
    list_display = ["name", "cost"]
    search_fields = ["identifier", "name_en", "name_fi", "name_sv"]
    filter_horizontal = ("requirements",)
    readonly_fields = ["created_at", "updated_at"]


class RequirementAdmin(OrderByNameMixin, AuditModelAdmin):
    list_display = ["name", "type", "value"]
    search_fields = ["name_en", "name_fi", "name_sv", "type"]
    readonly_fields = ["created_at", "updated_at"]


class RoleAdmin(OrderByNameMixin, AuditModelAdmin):
    list_display = ["name", "parent", "owner"]
    search_fields = ["identifier", "name_en", "name_fi", "name_sv"]
    autocomplete_fields = ["parent", "owner", "organisation"]
    readonly_fields = ["created_at", "updated_at"]
    filter_horizontal = (
        "approvers",
        "inviters",
        "permissions",
        "requirements",
    )
