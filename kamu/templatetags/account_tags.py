import logging

from django import template
from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.validators import URLValidator
from django.urls import reverse
from django.utils.translation import gettext_lazy as _

from kamu.models.account import Account

logger = logging.getLogger(__name__)
register = template.Library()


@register.simple_tag
def manage_link(account: Account) -> str:
    """
    Return a link for managing the account, if available.
    """
    url_validator = URLValidator(schemes=("http", "https"))

    account_actions = getattr(settings, "ACCOUNT_ACTIONS", {})
    action = account_actions.get(account.type)
    if action == "create":
        link_text = _("Manage account")
        link = reverse("account-detail", kwargs={"pk": account.pk})
        return f'<a href="{link}" class="btn btn-primary mb-2">{link_text}</a>'
    else:
        try:
            url_validator(action)
        except ValidationError:
            return ""
        link_text = _("Manage in external service")
        return f'<a href="{action}" class="btn btn-primary mb-2" target="_blank" rel="noopener">{link_text}</a>'
