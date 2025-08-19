"""
Django admin site configuration for the identity models.
"""

from django.contrib.auth.admin import GroupAdmin, UserAdmin
from rest_framework.authtoken.admin import TokenAdmin

from kamu.admin.customization import AuditModelAdmin


class AuditUserAdmin(AuditModelAdmin, UserAdmin):
    """
    Customized class for Django UserAdmin that adds Kamu auditing.
    """

    readonly_fields = ["date_joined", "last_login"]


class AuditGroupAdmin(AuditModelAdmin, GroupAdmin):
    """
    Customized class for Django GroupAdmin that adds Kamu auditing.
    """


class AuditTokenAdmin(AuditModelAdmin, TokenAdmin):
    """
    Customized TokenAdmin to limit displaying token and adding Kamu auditing.
    """

    raw_id_fields = ["user"]
    list_display = ["user", "created"]
