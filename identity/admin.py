from django.contrib import admin

from identity.models import Attribute, AttributeType, Identifier, Identity


class AttributeAdmin(admin.ModelAdmin):
    list_display = ["identity", "attribute_type"]
    search_fields = [
        "identity__name",
        "identity__user__username",
        "attribute_type__identifier",
        "value",
    ]


admin.site.register(Attribute, AttributeAdmin)


class AttributeTypeAdmin(admin.ModelAdmin):
    list_display = ["identifier", "name", "multi_value", "unique"]
    list_filter = ["multi_value", "unique"]
    search_fields = ["identifier", "name_en", "name_fi", "name_sv"]


admin.site.register(AttributeType, AttributeTypeAdmin)


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
    list_display = ["name"]
    list_filter = ["roles__identifier"]
    search_fields = [
        "name",
        "user__username",
        "roles__identifier",
    ]


admin.site.register(Identity, IdentityAdmin)
