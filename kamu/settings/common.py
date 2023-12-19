"""
Common settings file used by Kamu service

Loaded by environment specific settings files
"""
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import django_stubs_ext
from django.contrib.messages import constants as messages
from django.utils.translation import gettext_lazy as _
from django_stubs_ext import StrOrPromise

# Monkeypatching Django, so stubs will work for all generics,
# see: https://github.com/typeddjango/django-stubs
django_stubs_ext.monkeypatch()

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent.parent

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/4.2/howto/deployment/checklist/


# Application definition

INSTALLED_APPS: list[str] = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "crispy_forms",
    "crispy_bootstrap5",
    "rest_framework",
    "drf_spectacular",
    "base",
    "role",
    "identity",
]

CRISPY_ALLOWED_TEMPLATE_PACKS: str = "bootstrap5"

CRISPY_TEMPLATE_PACK: str = "bootstrap5"

MIDDLEWARE: list[str] = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.locale.LocaleMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

REST_FRAMEWORK: dict[str, Any] = {
    "DEFAULT_AUTHENTICATION_CLASSES": ("rest_framework.authentication.SessionAuthentication",),
    "TEST_REQUEST_DEFAULT_FORMAT": "json",
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
    "DEFAULT_PERMISSION_CLASSES": ("rest_framework.permissions.IsAuthenticated",),
    "DEFAULT_THROTTLE_CLASSES": [
        "rest_framework.throttling.AnonRateThrottle",
        "rest_framework.throttling.UserRateThrottle",
    ],
    "DEFAULT_THROTTLE_RATES": {"anon": "5/min", "user": "100/min"},
}

SPECTACULAR_SETTINGS: dict[str, Any] = {
    "TITLE": "Kamu API",
    "DESCRIPTION": "REST API for identities and roles.",
    "VERSION": "0.1.0",
    "SERVE_INCLUDE_SCHEMA": False,
    "SCHEMA_PATH_PREFIX": r"/api/v[0-9]",
}

ROOT_URLCONF: str = "kamu.urls"

TEMPLATES: list[dict[str, Any]] = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

AUTHENTICATION_BACKENDS: Sequence[str] = (
    "django.contrib.auth.backends.ModelBackend",
    "base.auth.ShibbolethBackend",
    "base.auth.GoogleBackend",
    "base.auth.EmailSMSBackend",
)

WSGI_APPLICATION: str = "kamu.wsgi.application"

# Password validation
# https://docs.djangoproject.com/en/4.2/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS: list[dict[str, str]] = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]


# Internationalization
# https://docs.djangoproject.com/en/4.2/topics/i18n/

LANGUAGE_CODE: str = "en"

LANGUAGES: list[tuple[str, StrOrPromise]] = [
    ("en", _("English")),
    ("fi", _("Finnish")),
    ("sv", _("Swedish")),
]


TIME_ZONE: str = "Europe/Helsinki"

USE_I18N: bool = True

USE_TZ: bool = True

# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/4.2/howto/static-files/

STATIC_URL: str = "static/"

LOGIN_URL: str = "/login/"

DEFAULT_AUTO_FIELD: str = "django.db.models.BigAutoField"

LOGOUT_REDIRECT_URL: str = "/"

ROLE_HIERARCHY_MAXIMUM_DEPTH: int = 4

# Allow use of 900-series Finnish personal identity codes
ALLOW_TEST_FPIC: bool = False

# Bootstrap alert classes for Django messages
MESSAGE_TAGS: dict[int, str] = {
    messages.DEBUG: "alert-secondary",
    messages.INFO: "alert-info",
    messages.SUCCESS: "alert-success",
    messages.WARNING: "alert-warning",
    messages.ERROR: "alert-danger",
}

LOGIN_REDIRECT_URL: str = "/"

SAML_GROUP_PREFIXES: list[str] = ["grp-", "hy-", "sys-"]

SAML_ATTR_EPPN: str = "shib_eduPersonPrincipalName"
SAML_ATTR_GIVEN_NAMES: str = "shib_givenName"
SAML_ATTR_SURNAME: str = "shib_sn"
SAML_ATTR_EMAIL: str = "shib_mail"
SAML_ATTR_GROUPS: str = "shib_hyGroupCn"

OIDC_GOOGLE_SUB: str = "OIDC_CLAIM_sub"
OIDC_GOOGLE_GIVEN_NAME: str = "OIDC_CLAIM_given_name"
OIDC_GOOGLE_FAMILY_NAME: str = "OIDC_CLAIM_family_name"
OIDC_GOOGLE_EMAIL: str = "OIDC_CLAIM_email"

# purge stale data this many days after expiry
PURGE_DELAY_DAYS: int = 730
