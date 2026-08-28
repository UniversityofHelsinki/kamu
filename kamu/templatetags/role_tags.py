import logging

from django import template

from kamu.models.role import Permission, Role

logger = logging.getLogger(__name__)
register = template.Library()


@register.simple_tag
def role_allows_permission(
    role: Role, permission_type: Permission.Type = Permission.Type.GENERIC, identifier: str = "", value: str = ""
) -> bool:
    """
    Check if a role allows a specific permission based on type, identifier, and value.
    """
    if (
        identifier
        and value
        and role.get_permissions().filter(type=permission_type, identifier=identifier, value=value).exists()
    ):
        return True
    elif identifier and role.get_permissions().filter(type=permission_type, identifier=identifier).exists():
        return True
    elif value and role.get_permissions().filter(type=permission_type, value=value).exists():
        return True
    return False
