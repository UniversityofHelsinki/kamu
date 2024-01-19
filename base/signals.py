"""
Signals for base app
"""
from typing import Any, Type

from django.contrib.auth.models import Group
from django.db import transaction
from django.db.models.signals import post_save
from django.dispatch import receiver

from base.utils import set_default_permissions


@receiver(post_save, sender=Group)
def post_group_create(sender: Type[Group], instance: Group, created: bool, **kwargs: Any) -> None:
    """
    Add permissions to groups after they are created.

    Use transaction.on_commit as m2m fields are saved after the group is saved.
    """

    def add_groups() -> None:
        if created:
            set_default_permissions(instance)

    transaction.on_commit(add_groups)
