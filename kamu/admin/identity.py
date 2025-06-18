"""
Django admin site configuration for the identity models.
"""

from kamu.admin.customization import AuditModelAdmin


class ContractAdmin(AuditModelAdmin):
    list_display = ["identity", "template"]
    search_fields = [
        "identity__given_names",
        "identity__surname",
        "identity__given_name_display",
        "identity__surname_display",
        "identity__user__username",
        "template__type",
    ]
    autocomplete_fields = ["identity"]


class ContractTemplateAdmin(AuditModelAdmin):
    list_display = ["type", "name", "version"]
    search_fields = [
        "type",
        "name_en",
        "name_fi",
        "name_sv",
    ]


class EmailAddressAdmin(AuditModelAdmin):
    list_display = ["identity", "address"]
    search_fields = [
        "identity__given_names",
        "identity__surname",
        "identity__given_name_display",
        "identity__surname_display",
        "identity__user__username",
        "address",
    ]
    autocomplete_fields = ["identity"]


class IdentifierAdmin(AuditModelAdmin):
    list_display = ["identity", "type"]
    search_fields = [
        "identity__given_names",
        "identity__surname",
        "identity__user__username",
        "type",
        "value",
    ]
    autocomplete_fields = ["identity"]


class IdentityAdmin(AuditModelAdmin):
    list_display = ["given_names", "surname", "assurance_level"]
    list_filter = ["roles__identifier"]
    search_fields = [
        "given_names",
        "surname",
        "given_name_display",
        "surname_display",
        "user__username",
        "roles__identifier",
    ]
    autocomplete_fields = ["user"]
    filter_horizontal = ("nationality",)


class PhoneNumberAdmin(AuditModelAdmin):
    list_display = ["identity", "number"]
    search_fields = [
        "identity__given_names",
        "identity__surname",
        "identity__given_name_display",
        "identity__surname_display",
        "identity__user__username",
        "number",
    ]
    autocomplete_fields = ["identity"]
