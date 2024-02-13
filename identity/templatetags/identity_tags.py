from django import template

from identity.models import Identity

register = template.Library()


@register.simple_tag
def get_gender_value(name: str) -> Identity.Gender:
    return Identity.Gender[name]
