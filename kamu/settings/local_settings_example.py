"""
Example local settings file.

Copy this to local_settings.py and modify as needed.
"""

DEBUG = False

SECRET_KEY = "insecure-secret-key-change-for-production"

ALLOWED_HOSTS = [".local", ".localhost", "127.0.0.1", "[::1]"]

# Database
# https://docs.djangoproject.com/en/dev/ref/settings/#databases
DATABASES = {
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

SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
CSRF_COOKIE_SECURE = True
CSRF_COOKIE_HTTPONLY = True
SESSION_EXPIRE_AT_BROWSER_CLOSE = True

TIME_ZONE = "EET"

# Email backend, see https://docs.djangoproject.com/en/dev/topics/email/
# EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
EMAIL_BACKEND = "django.core.mail.backends.console.EmailBackend"

# Email address used as send address
SERVER_EMAIL = "noreply@example.org"

# Will receive notifications of changes if error 500 occurs
# Format should be a list of tuples of (Full name, email address).
# Example: [('John', 'john@example.com'), ('Mary', 'mary@example.com')]
# ADMINS = []

# Role hierarchy maximum depth, 1 = no hierarchy, 2 = parent and child, etc.
ROLE_HIERARCHY_MAXIMUM_DEPTH = 4

# Path to static files for collection
STATIC_ROOT = "/path/to/rr/static/"

# Used to generate tokens
TOKEN_SECRET_KEY = "insecure-hash-key-change-for-production"
# Time limit until a new token with same type and linke dobject can be created (in seconds)
TOKEN_TIME_LIMIT_NEW = 60
# Number of tries for verifying tokens
TOKEN_VERIFICATION_TRIES = 3
# Token lifetime (in seconds)
TOKEN_LIFETIME = 30 * 60  # 30 minutes
# Invite lifetime (in seconds)
TOKEN_LIFETIME_INVITE = 30 * 24 * 60 * 60  # 30 days
