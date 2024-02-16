"""
Signals for kamu app
"""

from typing import Any, Type

from django.contrib.auth.models import Group
from django.db import transaction
from django.db.models.signals import post_delete, post_save
from django.dispatch import receiver

from kamu.models.contract import Contract
from kamu.models.identity import EmailAddress, Identifier, Identity, PhoneNumber
from kamu.models.membership import Membership
from kamu.utils.auth import set_default_permissions


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


@receiver(post_save, sender=Contract)
@receiver(post_save, sender=EmailAddress)
@receiver(post_save, sender=Membership)
@receiver(post_save, sender=Identifier)
@receiver(post_save, sender=PhoneNumber)
def identity_update_on_save(instance: object, **kwargs: Any) -> None:
    """
    Update identity's modified timestamp after related objects are saved.
    """
    if instance and hasattr(instance, "identity") and isinstance(instance.identity, Identity):
        instance.identity.save()


@receiver(post_delete, sender=Contract)
@receiver(post_delete, sender=EmailAddress)
@receiver(post_delete, sender=Membership)
@receiver(post_delete, sender=Identifier)
@receiver(post_delete, sender=PhoneNumber)
def identity_update_on_delete(instance: object, **kwargs: Any) -> None:
    """
    Update identity's modified timestamp after related objects are deleted.
    """
    if instance and hasattr(instance, "identity") and isinstance(instance.identity, Identity):
        instance.identity.save()
