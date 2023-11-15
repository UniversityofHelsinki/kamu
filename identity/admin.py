"""
Django admin site configuration for the identity app.
"""

from django.contrib import admin

from identity.models import EmailAddress, Identifier, Identity, PhoneNumber


class EmailAddressAdmin(admin.ModelAdmin):
    list_display = ["identity", "address"]
    search_fields = [
        "identity__display_name",
        "identity__user__username",
        "address",
    ]
    autocomplete_fields = ["identity"]


admin.site.register(EmailAddress, EmailAddressAdmin)


class IdentifierAdmin(admin.ModelAdmin):
    list_display = ["identity", "type"]
    search_fields = [
        "identity__name",
        "identity__user__username",
        "type",
        "value",
    ]
    autocomplete_fields = ["identity"]


admin.site.register(Identifier, IdentifierAdmin)


class IdentityAdmin(admin.ModelAdmin):
    list_display = ["given_names", "surname", "nickname"]
    list_filter = ["roles__identifier"]
    search_fields = [
        "given_names",
        "surname",
        "nickname",
        "user__username",
        "roles__identifier",
    ]
    autocomplete_fields = ["user"]


admin.site.register(Identity, IdentityAdmin)


class PhoneNumberAdmin(admin.ModelAdmin):
    list_display = ["identity", "number"]
    search_fields = [
        "identity__display_name",
        "identity__user__username",
        "number",
    ]
    autocomplete_fields = ["identity"]


admin.site.register(PhoneNumber, PhoneNumberAdmin)
