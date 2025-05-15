"""
Django admin site configuration for the organisation models.
"""

from kamu.admin.customization import AuditModelAdmin


class OrganisationAdmin(AuditModelAdmin):
    list_display = ["name", "code", "parent"]
    search_fields = ["identifier", "name_en", "name_fi", "name_sv", "abbreviation", "code"]
    autocomplete_fields = ["parent"]
