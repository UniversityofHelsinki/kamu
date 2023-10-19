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
    search_fields = [
        "name",
    ]


admin.site.register(Permission, PermissionAdmin)


class RoleAdmin(admin.ModelAdmin):
    list_display = ["name", "parent", "owner"]
    search_fields = [
        "name",
        "parent__name",
    ]


admin.site.register(Role, RoleAdmin)
