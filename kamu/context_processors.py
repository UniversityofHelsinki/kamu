"""
Custom context processors for Kamu.
"""

from typing import Any

from django.conf import settings
from django.http import HttpRequest
from django.utils.translation import get_language

from kamu.utils.generic import create_help_link


def links(request: HttpRequest) -> dict[str, Any]:
    lang = get_language()
    return {
        "HELP_LINK_USERS": create_help_link(getattr(settings, "HELP_LINK_USERS", ""), lang),
        "HELP_LINK_MANAGERS": create_help_link(getattr(settings, "HELP_LINK_MANAGERS", ""), lang),
    }
