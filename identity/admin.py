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


admin.site.register(EmailAddress, EmailAddressAdmin)


class IdentifierAdmin(admin.ModelAdmin):
    list_display = ["identity", "type"]
    search_fields = [
        "identity__name",
        "identity__user__username",
        "type",
        "value",
    ]


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


admin.site.register(Identity, IdentityAdmin)


class PhoneNumberAdmin(admin.ModelAdmin):
    list_display = ["identity", "number"]
    search_fields = [
        "identity__display_name",
        "identity__user__username",
        "number",
    ]


admin.site.register(PhoneNumber, PhoneNumberAdmin)
