"""
Django admin site configuration for the role models.
"""

from kamu.admin.customization import (
    AuditModelAdmin,
    CopyAsTemplateMixin,
    OrderByNameMixin,
)


class PermissionAdmin(OrderByNameMixin, CopyAsTemplateMixin, AuditModelAdmin):
    list_display = ["name", "cost"]
    list_filter = ["requirements"]
    search_fields = ["identifier", "name_en", "name_fi", "name_sv"]
    filter_horizontal = ("requirements",)
    readonly_fields = ["created_at", "updated_at"]


class RequirementAdmin(OrderByNameMixin, AuditModelAdmin):
    list_display = ["name", "type", "value"]
    list_filter = ["type"]
    search_fields = ["name_en", "name_fi", "name_sv", "type"]
    readonly_fields = ["created_at", "updated_at"]


class RoleAdmin(OrderByNameMixin, CopyAsTemplateMixin, AuditModelAdmin):
    list_display = ["name", "parent", "owner"]
    list_filter = ["permissions", "requirements"]
    search_fields = ["identifier", "name_en", "name_fi", "name_sv"]
    autocomplete_fields = ["parent", "owner", "organisation"]
    readonly_fields = ["created_at", "updated_at"]
    filter_horizontal = (
        "approvers",
        "inviters",
        "permissions",
        "requirements",
    )
