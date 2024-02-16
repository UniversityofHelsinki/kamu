"""
Django admin site configuration for the role models.
"""

from django.contrib import admin


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
