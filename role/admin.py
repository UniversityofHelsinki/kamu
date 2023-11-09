"""
Django admin site configuration for the role app.
"""

from django.contrib import admin

from role.models import Membership, Permission, Role


class MembershipAdmin(admin.ModelAdmin):
    list_display = ["identity", "role", "start_date", "expire_date"]
    search_fields = [
        "identity",
        "role__name",
        "approver",
    ]


admin.site.register(Membership, MembershipAdmin)


class PermissionAdmin(admin.ModelAdmin):
    list_display = ["name", "cost"]
    search_fields = ["identifier", "name_en", "name_fi", "name_sv"]


admin.site.register(Permission, PermissionAdmin)


class RoleAdmin(admin.ModelAdmin):
    list_display = ["name", "parent", "owner"]
    search_fields = ["identifier", "name_en", "name_fi", "name_sv"]


admin.site.register(Role, RoleAdmin)
