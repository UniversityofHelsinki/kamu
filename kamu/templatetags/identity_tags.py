from django import template

from kamu.models.identity import Identity

register = template.Library()


@register.simple_tag
def get_gender_value(name: str) -> Identity.Gender:
    return Identity.Gender[name]
