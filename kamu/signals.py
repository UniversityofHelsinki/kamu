"""
Signals for kamu app
"""

from typing import Any, Type

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.db import transaction
from django.db.models.signals import m2m_changed, post_delete, post_save, pre_delete
from django.dispatch import receiver

from kamu.models.contract import Contract
from kamu.models.identity import EmailAddress, Identifier, Identity, PhoneNumber
from kamu.models.membership import Membership
from kamu.models.role import Permission, Requirement, Role
from kamu.utils.audit import AuditLog
from kamu.utils.auth import set_default_permissions

audit_log = AuditLog()
UserModel = get_user_model()


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


@receiver(post_save, sender=Permission)
@receiver(post_save, sender=Requirement)
def role_update_on_related_save(instance: object, **kwargs: Any) -> None:
    """
    Update role or permission modified timestamp after related permissions or requirements are saved.
    """
    if instance:
        if hasattr(instance, "role_set"):
            for role in instance.role_set.all():
                role.save()
        if hasattr(instance, "role_requirements"):
            for permission in instance.role_requirements.all():
                permission.save()
        if hasattr(instance, "permission_requirements"):
            for permission in instance.permission_requirements.all():
                permission.save()


@receiver(m2m_changed, sender=Role.permissions.through)
@receiver(m2m_changed, sender=Role.requirements.through)
@receiver(m2m_changed, sender=Permission.requirements.through)
def role_update_on_permission_change(instance: object, **kwargs: Any) -> None:
    """
    Update role or permission modified timestamp if related permissions or requirements are added or removed.
    """
    if instance and hasattr(instance, "save"):
        if callable(instance.save):
            instance.save()


@receiver(pre_delete, sender=Permission)
def role_update_on_permission_delete(instance: Permission, **kwargs: Any) -> None:
    """
    Remove roles' permission and update timestamp before permission is deleted.
    """
    if instance:
        for role in instance.role_set.all():
            role.permissions.remove(instance)
            role.save()


@receiver(pre_delete, sender=Requirement)
def role_update_on_requirement_delete(instance: Requirement, **kwargs: Any) -> None:
    """
    Remove roles' requirement and update timestamp before requirement is deleted.
    """
    if instance:
        for role in instance.role_requirements.all():
            role.requirements.remove(instance)
            role.save()


@receiver(post_save, sender=Role)
def membership_update_on_role_save(instance: Role, **kwargs: Any) -> None:
    """
    Update memberships' status and modified timestamp after related role is saved.
    """
    if instance:
        for membership in instance.membership_set.all():
            membership.save()
