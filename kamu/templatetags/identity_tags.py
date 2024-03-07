import logging

from django import template
from django.conf import settings
from django.utils.html import escape

from kamu.models.identity import Identifier, Identity

logger = logging.getLogger(__name__)
register = template.Library()


@register.simple_tag
def get_gender_value(name: str) -> Identity.Gender:
    return Identity.Gender[name]


@register.simple_tag
def matching_attributes(identity: Identity, email: str = "", phone: str = "", fpic: str = "") -> str:
    """
    Return a string of all matching or public attributes for an identity.
    Bold the ones that match exact search terms.
    """
    matching = []
    public_email_domains = getattr(settings, "PUBLIC_EMAIL_DOMAINS", [])
    for address in identity.email_addresses.values_list("address", flat=True):
        if address == email:
            matching.append(f"<b>{escape(address)}</b>")
        elif address.split("@")[1] in public_email_domains:
            matching.append(escape(address))
    if phone and identity.phone_numbers.filter(number=phone).exists():
        matching.append(f"<b>{escape(phone)}</b>")
    if fpic and (identity.fpic == fpic or identity.identifiers.filter(type=Identifier.Type.FPIC, value=fpic).exists()):
        matching.append(f"<b>{escape(fpic)}</b>")
    return ", ".join(matching)


@register.simple_tag
def matching_attributes_ldap(result: dict[str, str], email: str = "", fpic: str = "") -> str:
    """
    Return a string of all matching or public attributes for LDAP result.
    Bold the ones that match exact search terms.
    """
    matching = []
    public_email_domains = getattr(settings, "PUBLIC_EMAIL_DOMAINS", [])
    attributes = settings.LDAP_SEARCH_ATTRIBUTES
    try:
        if "email" in attributes:
            address = result.get(attributes["email"]["email"]["attribute"])
            if address:
                if address == email:
                    matching.append(f"<b>{escape(address)}</b>")
                elif address.split("@")[1] in public_email_domains:
                    matching.append(escape(address))
        if "fpic" in attributes:
            fpic_value = result.get(attributes["fpic"]["fpic"]["attribute"])
            value_prefix = attributes["fpic"]["fpic"]["value_prefix"]
            if fpic_value and fpic_value == f"{value_prefix}{fpic}":
                matching.append(f"<b>{escape(fpic_value.removeprefix(value_prefix))}</b>")
    except KeyError as e:
        log_msg = f"Incorrect LDAP_SEARCH_ATTRIBUTES, KeyError: { e }"
        logger.error(log_msg)
        return ""
    return ", ".join(matching)
