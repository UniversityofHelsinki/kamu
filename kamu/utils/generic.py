"""
Generic helper functions
"""

from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.validators import URLValidator


def create_help_link(link_address: str, lang: str = "en") -> str:
    """
    Creates University of Helsinki IT Helpdesk link if numeric link_address is given.
    Otherwise, returns link address or HELP_LINK_BASE if link address is not url.
    """
    if link_address.isdigit():
        link_base = getattr(settings, "HELP_LINK_BASE", "")
        match lang:
            case "en":
                return link_base + lang + "/help/" + link_address
            case "fi":
                return link_base + "help/" + link_address
            case "sv":
                return link_base + lang + "/help/" + link_address
    validate_url = URLValidator()
    try:
        validate_url(link_address)
    except ValidationError:
        return getattr(settings, "HELP_LINK_BASE", "")
    return link_address
