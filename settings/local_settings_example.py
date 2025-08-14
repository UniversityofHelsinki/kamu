"""
Example local settings file.

Copy this to local_settings.py and modify as needed.
"""

from collections.abc import Sequence
from typing import Any

DEBUG: bool = False

SECRET_KEY: str = "insecure-secret-key-change-for-production"

ALLOWED_HOSTS: list[str] = [".local", ".localhost", "127.0.0.1", "[::1]"]

# Service base URL for links in emails, scheme://url:port
SERVICE_LINK_URL: str = "https://localhost:8000"

# Set locale path for translations, otherwise app translations may get overridden.
LOCALE_PATHS = [
    "/path/to/kamu/kamu/locale",
]

# Database
# https://docs.djangoproject.com/en/dev/ref/settings/#databases
DATABASES: dict[str, dict[str, Any]] = {
    "default": {
        "ENGINE": "django.db.backends.mysql",
        "NAME": "kamu",
        "USER": "kamu",
        "PASSWORD": "kamu",
        "HOST": "localhost",
        "OPTIONS": {
            "init_command": "SET sql_mode='STRICT_TRANS_TABLES'",
        },
    }
}

try:
    from .local_logging import *
except ModuleNotFoundError:
    from .logging import *

SESSION_COOKIE_SECURE: bool = True
SESSION_COOKIE_HTTPONLY: bool = True
CSRF_COOKIE_SECURE: bool = True
CSRF_COOKIE_HTTPONLY: bool = True
SESSION_EXPIRE_AT_BROWSER_CLOSE: bool = True

TIME_ZONE: str = "Europe/Helsinki"

# Email backend, see https://docs.djangoproject.com/en/dev/topics/email/
# EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
EMAIL_BACKEND: str = "django.core.mail.backends.console.EmailBackend"

# Email address used as send address for error messages to site admins
SERVER_EMAIL: str = "noreply@example.org"

# Token verification posts will be sent from this address. Using DEFAULT_FROM_EMAIL if this is not set.
TOKEN_FROM_EMAIL: str = "noreply@example.org"

# Email address for accessibility contact
ACCESSIBILITY_CONTACT_EMAIL: str = "accessibility@example.org"

# Maximum number of contacts allowed for user, per type (email address, phone number)
CONTACT_LIMIT: int = 3

# Used in locally created usernames, i.e. in email and SMS registration.
LOCAL_IDENTITY_SUFFIX: str = "@local_identity"

# Groups whose members have mass invite permissions top roles, up to INT members at time.
# Users must also have invite permissions to the role.
MASS_INVITE_PERMISSION_GROUPS: dict[str, int] = {
    "mass_invite_2": 2,
}

# Will receive notifications of changes if error 500 occurs
# Format should be a list of tuples of (Full name, email address).
# Example: [('John', 'john@example.com'), ('Mary', 'mary@example.com')]
# ADMINS = []

# Role hierarchy maximum depth, 1 = no hierarchy, 2 = parent and child, etc.
ROLE_HIERARCHY_MAXIMUM_DEPTH: int = 4

# Path to static files for collection
STATIC_ROOT: str = "/path/to/rr/static/"

# Used to generate tokens
TOKEN_SECRET_KEY: str = "insecure-hash-key-change-for-production"
# Time limit until a new token with same type and linke dobject can be created (in seconds)
TOKEN_TIME_LIMIT_NEW: int = 60
# Number of tries for verifying tokens
TOKEN_VERIFICATION_TRIES: int = 3
# Token lifetime (in seconds)
TOKEN_LIFETIME: int = 30 * 60  # 30 minutes
# Invite lifetime (in seconds)
TOKEN_LIFETIME_INVITE: int = 30 * 24 * 60 * 60  # 30 days
# How long registration process can take (in seconds)
INVITATION_PROCESS_TIME: int = 60 * 60  # 1 hour
# How long link identifier session variable is valid (in seconds)
LINK_IDENTIFIER_TIME_LIMIT: int = 5 * 60  # 5 minutes

# Memberships are flagged as expiring soon this many days in advance
EXPIRING_LIMIT_DAYS: int = 30  # 30 days

SMS_API_URL: str = "https://api-gateway.example.org/sms/send"
SMS_AUTH_HEADER: str = "X-Api-Key"
SMS_API_KEY: str = ""
SMS_API_TIMEOUT: int = 3
# SMS messages will be logged instead of sent to API if SMS_DEBUG is True.
SMS_DEBUG: bool = False

LDAP_SEARCH_FOR_INVITES: bool = True  # Defaults to True
LDAP_SEARCH_FOR_IDENTITIES: bool = False  # Defaults to False

LDAP_SETTINGS: dict[str, Any] = {
    "HOST": "127.0.0.1",
    "PORT": 389,
    "USER": "ou=ldapuser,dc=example,dc=org",
    "PASSWORD": "ldapuser_password",
    "TIMEOUT_SECONDS": 5,
    "USE_LDAPS": True,
    "CACERTFILE": "/path/to/cacert.pem",  # set None to use system default
    "IGNORE_TLS_CHECK": False,
    "SEARCH_BASE": "ou=users,dc=example,dc=org",
}
# If LDAP search would return more results, ask users to refine search.
LDAP_SEARCH_LIMIT: int = 50
# If Identity search would return more results, ask users to refine search.
KAMU_IDENTITY_SEARCH_LIMIT: int = 50

# If OIDC_LOGOUT_PATH are given and login-view is in OIDC_VIEWS,
# redirect user to logout url + redirect url, just before linking identifier.
# This is required if using mod_auth_openidc and multiple OIDC providers, as
# mod_auth_openidc does not support multiple simultaneous sessions.
OIDC_LOGOUT_PATH: str = "/login/redirecturi?logout="
OIDC_VIEWS: list[str] = ["login-google", "login-microsoft"]

# SAML_LOGOUT paths are used to redirect user back to Shibboleth SP process.
SAML_LOGOUT_LOCAL_PATH: str = "/Shibboleth.sso/default/Logout"
SAML_LOGOUT_SUOMIFI_PATH: str = "/Shibboleth.sso/suomifi/Logout"
SAML_LOGOUT_HAKA_PATH: str = "/Shibboleth.sso/haka/Logout"
SAML_LOGOUT_EDUGAIN_PATH: str = "/Shibboleth.sso/edugain/Logout"

# Uncomment login backends you want to activate.
AUTHENTICATION_BACKENDS: Sequence[str] = (
    # "django.contrib.auth.backends.ModelBackend",
    # "kamu.backends.ShibbolethLocalBackend",
    # "kamu.backends.ShibbolethEdugainBackend",
    # "kamu.backends.ShibbolethHakaBackend",
    # "kamu.backends.GoogleBackend",
    # "kamu.backends.MicrosoftBackend",
    # "kamu.backends.SuomiFiBackend",
    # "kamu.backends.EmailSMSBackend",
)

# List of group prefixes that are synced for each backend.
BACKEND_GROUP_PREFIXES: dict[str, list[str]] = {
    "kamu.backends.ShibbolethLocalBackend": ["grp-", "hy-", "sys-"],
}
# When logging in, remove user's groups that are matching prefixes from other backends.
REMOVE_GROUPS_WITH_OTHER_BACKENDS: bool = True

# Limit role owner access to listed backends
# LIMIT_OWNER_ACCESS_TO_BACKENDS: Sequence[str] = ("kamu.backends.ShibbolethLocalBackend",)

# Limit staff and superuser access to listed backends
# LIMIT_STAFF_ACCESS_TO_BACKENDS: Sequence[str] = ("kamu.backends.ShibbolethLocalBackend",)

# Limit staff and superuser access to listed ip ranges
# LIMIT_STAFF_ACCESS_TO_IPS: Sequence[str] = "127.0.0.1/16"

# Limit access to users with certain groups to ip ranges
# LIMIT_GROUP_ACCESS_TO_IPS: dict[str, list[str]] = {
#    "grp-admin": ["127.0.0.1/16"],
# }

# Emails with these domains are considered public and shown in identity search results
PUBLIC_EMAIL_DOMAINS: list[str] = ["example.net", "example.org"]

# When searching identities, do not search names if matching identifier is found.
SKIP_NAME_SEARCH_IF_IDENTIFIER_MATCHES: bool = True

# When searching identities, do not show LDAP search results which are also found from Kamu.
FILTER_KAMU_RESULTS_FROM_LDAP_RESULTS: bool = True

HELP_LINK_MANAGERS: str = "https://helpdesk.it.helsinki.fi/"
HELP_LINK_USERS: str = "https://helpdesk.it.helsinki.fi/"

# Services that are allowed to each light account. List of identifiers.
LIGHT_ACCOUNT_DEFAULT_SERVICES: list[str] = ["https://attributetest.it.helsinki.fi/sp"]

# Account API URL, path is appended to this URL with urllib.parse.urljoin, so it should end with a slash.
ACCOUNT_API_URL: str = "https://localhost/accountapi/v1/"
ACCOUNT_API_KEY: str = "change-api-key"
# ACCOUNT_AUTH_HEADER: str = "apikey"
# ACCOUNT_API_TIMEOUT: int = 3
# ACCOUNT_API_VERIFY_SSL: bool = True
# ACCOUNT_API_CERT_FILE_PATH: str | None = "/path/to/cert.pem"
# ACCOUNT_API_KEY_FILE_PATH: str | None = "/path/to/key.pem"
# ACCOUNT_API_SUCCESS_CODES: list[int] = [200, 201, 204]

# Change API default paths. These are appended to ACCOUNT_API_URL with urllib.parse.urljoin.
# ACCOUNT_API_CREATE_PATH: str = "create"
# ACCOUNT_API_DISABLE_PATH: str =  "disable"
# ACCOUNT_API_ENABLE_PATH: str = "enable"
# ACCOUNT_API_CHANGE_PASSWORD_PATH: str = "changePassword"
# ACCOUNT_API_UPDATE_PATH: str = "update"
# ACCOUNT_API_UID_CHOICES_PATH: str = "generateUids"

ORGANISATION_API_URL: str = "https://localhost/organisation/info/v2"
ORGANISATION_API_KEY: str = "change-api-key"
# ORGANISATION_AUTH_HEADER: str = "X-Api-Key"
# ORGANISATION_API_TIMEOUT: int = 3
# ORGANISATION_API_VERIFY_SSL: bool = True
# ORGANISATION_API_CERT_FILE_PATH: str | None = "/path/to/cert.pem"
# ORGANISATION_API_KEY_FILE_PATH: str | None = "/path/to/key.pem"

# Change API default paths. These are appended to ACCOUNT_API_URL with urllib.parse.urljoin.
# ORGANISATION_API_STRUCTURE_PATH: str = "financeUnits"
# ORGANISATION_API_ABBREVIATION_PATH: str = "officialUnits"

# Change API object default keys.
# ORGANISATION_API_IDENTIFIER_KEY: str = uniqueId"
# ORGANISATION_API_NAME_EN_KEY: str = nameEn"
# ORGANISATION_API_NAME_FI_KEY: str = nameFi"
# ORGANISATION_API_NAME_SV_KEY: str = nameSv"
# ORGANISATION_API_CODE_KEY: str = code"
# ORGANISATION_API_ABBREVIATION_KEY: str = abbreviation"

# How many uid choices are given when creating a new account.
# ACCOUNT_UID_CHOICES_NUMBER: int = 5

# Actions to perform for external accounts. If value is create, create it through Accounts API.
# If value is URL, redirect user to that URL.
ACCOUNT_ACTIONS: dict[str, str] = {
    "lightaccount": "create",
    "account": "https://localhost/accountactivation",
}
# External account affiliations for create and update actions. First one is used as primary affiliation.
ACCOUNT_AFFILIATIONS: dict[str, list[str]] = {
    "lightaccount": ["affiliate"],
}

# External account types for create and update actions
ACCOUNT_TYPES: dict[str, int | str] = {
    "lightaccount": 9,
}
