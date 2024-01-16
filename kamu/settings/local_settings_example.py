"""
Example local settings file.

Copy this to local_settings.py and modify as needed.
"""

from typing import Any

DEBUG: bool = False

SECRET_KEY: str = "insecure-secret-key-change-for-production"

ALLOWED_HOSTS: list[str] = [".local", ".localhost", "127.0.0.1", "[::1]"]

# Service base URL for links in emails, scheme://url:port
SERVICE_LINK_URL: str = "https://localhost:8000"

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

TIME_ZONE: str = "EET"

# Email backend, see https://docs.djangoproject.com/en/dev/topics/email/
# EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
EMAIL_BACKEND: str = "django.core.mail.backends.console.EmailBackend"

# Email address used as send address for error messages to site admins
SERVER_EMAIL: str = "noreply@example.org"

# Token verification posts will be sent from this address. Using DEFAULT_FROM_EMAIL if this is not set.
TOKEN_FROM_EMAIL: str = "noreply@example.org"

# Maximum number of contacts allowed for user, per type (email address, phone number)
CONTACT_LIMIT: int = 3

# Used in locally created usernames, i.e. in email and SMS registration.
LOCAL_IDENTITY_SUFFIX: str = "@local_identity"

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

SMS_API_URL: str = "https://api-gateway.example.org/sms/send"
SMS_AUTH_HEADER: str = "X-Api-Key"
SMS_API_KEY: str = ""
SMS_API_TIMEOUT: int = 3
# SMS messages will be logged instead of sent to API if SMS_DEBUG is True.
SMS_DEBUG: bool = False

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
