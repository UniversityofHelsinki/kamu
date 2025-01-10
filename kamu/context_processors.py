"""
Custom context processors for Kamu.
"""

from typing import Any

from django.conf import settings
from django.http import HttpRequest


def links(request: HttpRequest) -> dict[str, Any]:
    return {
        "HELP_LINK_USERS": getattr(settings, "HELP_LINK_USERS", None),
        "HELP_LINK_MANAGERS": getattr(settings, "HELP_LINK_MANAGERS", None),
    }
