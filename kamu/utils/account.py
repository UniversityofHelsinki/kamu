"""
Helper functions for accounts
"""

import unicodedata

from django.conf import settings
from django.utils import timezone
from django_stubs_ext import StrOrPromise

from kamu.models.account import Account
from kamu.models.identity import Identifier, Identity
from kamu.models.membership import Membership
from kamu.models.role import Permission
from kamu.utils.audit import AuditLog

audit_log = AuditLog()


def get_light_account_external_identifiers(identity: Identity) -> list[str]:
    """
    Returns external identifiers for a light account.
    """
    identifiers = []
    for identifier in identity.identifiers.filter(deactivated_at__isnull=True):
        if identifier.type == Identifier.Type.EPPN:
            identifiers.append(f"EPPN:{identifier.value}")
        elif identifier.type == Identifier.Type.GOOGLE:
            identifiers.append(f"GOOGLE:{identifier.value}")
        elif identifier.type == Identifier.Type.MICROSOFT:
            identifiers.append(f"MICROSOFT:{identifier.value}")
    return identifiers


def get_light_account_services(identity: Identity) -> list[str]:
    """
    Returns external services for a light account.
    """
    default_services = getattr(settings, "LIGHT_ACCOUNT_DEFAULT_SERVICES", [])
    services = set()
    service_providers = identity.get_permissions().filter(type=Permission.Type.SERVICE)
    for service_provider in service_providers:
        services.add(service_provider.value)
    for service in default_services:
        services.add(service)
    return list(services)


def get_creatable_accounts(identity: Identity, include_external: bool = True) -> list[dict[str, StrOrPromise]]:
    """
    Returns list of creatable accounts for UI.

    Includes account permissions where action is defined in settings and user has no such account yet.

    Returned dicts including type, name and action.
    Name is Account.Type label for accounts created in Kamu and permission name for externally created accounts.
    """
    account_permissions = identity.get_permissions(permission_type=Permission.Type.ACCOUNT)
    account_permission_types = account_permissions.values_list("value", flat=True)
    existing_account_types = identity.useraccount.values_list("type", flat=True)
    creatable_accounts = []
    for account_type in set(account_permission_types) - set(existing_account_types):
        action = settings.ACCOUNT_ACTIONS.get(account_type, "")
        if action and (action == "create" or include_external):
            creatable_accounts.append(
                {
                    "type": account_type,
                    "name": (
                        Account.Type(account_type).label
                        if account_type in Account.Type and action == "create"
                        else account_permissions.get(value=account_type).name()
                    ),
                    "action": action,
                }
            )
    return creatable_accounts


def get_account_type(account_type: Account.Type) -> int | str:
    """
    Returns the numeric account type for the identity.
    """
    return settings.ACCOUNT_TYPES.get(account_type, 0)


def get_affiliation(account_type: Account.Type) -> list[str]:
    """
    Returns the affiliations for the identity.
    """
    return settings.ACCOUNT_AFFILIATIONS.get(account_type, ["affiliate"])


def get_account_base_membership(identity: Identity, account_type: Account.Type) -> Membership | None:
    """
    Get membership where the account is based on. This is an active membership which gives the required permission
    and which has the longest membership period left.

    Return None if no such membership exists.
    """
    memberships = Membership.objects.filter(identity=identity, status=Membership.Status.ACTIVE).order_by(
        "-expire_date"
    )
    for membership in memberships:
        for permission in membership.role.get_permissions():
            if permission.value == account_type:
                return membership
    return None


def get_gecos(identity: Identity) -> str:
    """
    Returns the gecos field for the identity.

    The field is normalized to ASCII and truncated to 127 characters.
    """
    normalized = unicodedata.normalize("NFKD", identity.display_name())
    ascii_encoded = normalized.encode("ascii", "ignore").decode("ascii")
    return ascii_encoded[:127]


def get_account_data(identity: Identity, account_type: Account.Type) -> dict[str, str | int | list[str] | None]:
    """
    Returns data for creating or updating a user account.
    """
    membership = get_account_base_membership(identity, account_type)
    unverified_email_permission = getattr(settings, "ACCOUNT_UNVERIFIED_EMAIL_PERMISSION", None)
    if (
        unverified_email_permission
        and identity.get_permissions().filter(identifier=unverified_email_permission).exists()
    ):
        email = identity.email_address(unverified=True)
    else:
        email = identity.email_address()
    data = {
        settings.ACCOUNT_ATTRIBUTES["accountType"]: get_account_type(account_type),
        settings.ACCOUNT_ATTRIBUTES["cn"]: identity.display_name(),
        settings.ACCOUNT_ATTRIBUTES["displayName"]: identity.display_name(),
        settings.ACCOUNT_ATTRIBUTES["eduPersonAffiliation"]: get_affiliation(account_type),
        settings.ACCOUNT_ATTRIBUTES["eduPersonPrimaryAffiliation"]: get_affiliation(account_type)[0],
        settings.ACCOUNT_ATTRIBUTES["gecos"]: get_gecos(identity),
        settings.ACCOUNT_ATTRIBUTES["givenName"]: identity.given_name_display,
        settings.ACCOUNT_ATTRIBUTES["kamuIdentifier"]: str(identity.kamu_id),
        settings.ACCOUNT_ATTRIBUTES["mail"]: email,
        settings.ACCOUNT_ATTRIBUTES["organizationUnit"]: (
            membership.role.organisation.code if membership and membership.role.organisation else None
        ),
        settings.ACCOUNT_ATTRIBUTES["schacExpiryDate"]: (
            membership.expire_date.isoformat() if membership else timezone.localdate().isoformat()
        ),
        settings.ACCOUNT_ATTRIBUTES["sn"]: identity.surname_display,
    }
    if account_type == Account.Type.LIGHT:
        data[settings.ACCOUNT_ATTRIBUTES["lightAccountExternalIdentifier"]] = get_light_account_external_identifiers(
            identity
        )
        data[settings.ACCOUNT_ATTRIBUTES["lightAccountService"]] = get_light_account_services(identity)
    return data


def get_minimum_password_length() -> int:
    """
    Returns the minimum password length from configuration, or default 8.
    """
    default: int = 8
    for setting in settings.ACCOUNT_PASSWORD_VALIDATORS:
        if setting["NAME"] == "django.contrib.auth.password_validation.MinimumLengthValidator":
            options = setting.get("OPTIONS", {})
            if isinstance(options, dict):
                return options.get("min_length", default)
    return default
