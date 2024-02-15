"""
Django admin site configuration for the role models.
"""

from django.contrib import admin


class MembershipAdmin(admin.ModelAdmin):
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


class PermissionAdmin(admin.ModelAdmin):
    list_display = ["name", "cost"]
    search_fields = ["identifier", "name_en", "name_fi", "name_sv"]


class RequirementAdmin(admin.ModelAdmin):
    list_display = ["name", "type", "value"]
    search_fields = ["name_en", "name_fi", "name_sv", "type"]


class RoleAdmin(admin.ModelAdmin):
    list_display = ["name", "parent", "owner"]
    search_fields = ["identifier", "name_en", "name_fi", "name_sv"]
    autocomplete_fields = ["parent", "owner"]
