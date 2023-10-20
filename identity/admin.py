from django.contrib import admin

from identity.models import Attribute, AttributeType, Identity


class AttributeAdmin(admin.ModelAdmin):
    list_display = ["identity", "attribute_type"]
    search_fields = [
        "identity__user__username",
        "attribute_type__name",
        "value",
    ]


admin.site.register(Attribute, AttributeAdmin)


class AttributeTypeAdmin(admin.ModelAdmin):
    list_display = ["name", "multi_value", "unique"]
    list_filter = ["multi_value", "unique"]
    search_fields = [
        "name",
    ]


admin.site.register(AttributeType, AttributeTypeAdmin)


class IdentityAdmin(admin.ModelAdmin):
    list_display = ["user"]
    list_filter = ["roles__name"]
    search_fields = [
        "user__display_name",
        "user__username",
        "roles__name",
    ]


admin.site.register(Identity, IdentityAdmin)
