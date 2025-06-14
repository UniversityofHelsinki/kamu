"""
Test setup for all tests.
"""

import datetime
from typing import Any

from django.conf import settings
from django.contrib.auth import get_user_model
from django.test import RequestFactory, TestCase
from django.utils import timezone
from rest_framework.test import APIRequestFactory, APITestCase

from kamu.models.account import Account
from kamu.models.contract import ContractTemplate
from kamu.models.identity import EmailAddress, Identity, Nationality, PhoneNumber
from kamu.models.membership import Membership
from kamu.models.organisation import Organisation
from kamu.models.role import Permission, Requirement, Role
from tests.data import (
    CONTRACT_TEMPLATES,
    NATIONALITIES,
    ORGANISATIONS,
    PERMISSIONS,
    REQUIREMENTS,
    ROLES,
    USERS,
)


def membership_new_save(self, *args: Any, **kwargs: Any) -> None:
    if not getattr(settings, "SKIP_MEMBERSHIP_SAVE", False):
        self.set_status()
    super(Membership, self).save(*args, **kwargs)


class TestData(TestCase):
    """
    Base test data for all tests.
    """

    UserModel = get_user_model()

    def create_user(self):
        self.user = self.UserModel.objects.create_user(**USERS["user"])
        return self.user

    def create_superuser(self):
        self.superuser = self.UserModel.objects.create_user(**USERS["superuser"])
        return self.superuser

    def create_identity(self, user=False, email=False, phone=False):
        if user and not self.user:
            self.create_user()
        self.identity = Identity.objects.create(
            user=self.user, given_names=USERS["user"]["first_name"], surname=USERS["user"]["last_name"]
        )
        if email:
            self.email_address = EmailAddress.objects.create(
                identity=self.identity, address="test@example.org", verified=True
            )
        if phone:
            self.phone_number = PhoneNumber.objects.create(identity=self.identity, number="+1234567890", verified=True)
        return self.identity

    def create_superidentity(self, user=True, email=False, phone=False):
        if user and not self.superuser:
            self.create_superuser()
        self.superidentity = Identity.objects.create(
            user=self.superuser, given_names=USERS["superuser"]["first_name"], surname=USERS["superuser"]["last_name"]
        )
        if email:
            self.email_address = EmailAddress.objects.create(
                identity=self.superidentity, address="super_test@example.org", verified=True
            )
        if phone:
            self.phone_number = PhoneNumber.objects.create(
                identity=self.superidentity,
                number="+1234000000",
            )
        return self.superidentity

    def create_organisation(self, name="testorg", parent=None):
        organisation = ORGANISATIONS[name].copy()
        organisation.pop("parent")
        if parent:
            return Organisation.objects.create(parent=parent, **organisation)
        return Organisation.objects.create(**organisation)

    def create_role(self, name="ext_employee", parent=None):
        role = ROLES[name].copy()
        organisation = role.pop("organisation")
        if organisation:
            role["organisation"], _ = Organisation.objects.get_or_create(identifier=organisation)
        else:
            role["organisation"] = None
        if parent:
            return Role.objects.create(parent=parent, **role)
        return Role.objects.create(**role)

    def create_membership(
        self,
        role,
        identity=None,
        start_delta_days=0,
        expire_delta_days=0,
        reason="Test",
        approver=None,
        inviter=None,
        invite_email_address="",
        status=None,
    ):
        Membership.save = membership_new_save
        start_date = timezone.now().date() + datetime.timedelta(days=start_delta_days)
        expire_date = timezone.now().date() + datetime.timedelta(days=expire_delta_days)
        if status:
            with self.settings(SKIP_MEMBERSHIP_SAVE=True):
                return Membership.objects.create(
                    role=role,
                    identity=identity,
                    reason=reason,
                    start_date=start_date,
                    expire_date=expire_date,
                    approver=approver,
                    inviter=inviter,
                    invite_email_address=invite_email_address,
                    status=status,
                )
        return Membership.objects.create(
            role=role,
            identity=identity,
            reason=reason,
            start_date=start_date,
            expire_date=expire_date,
            approver=approver,
            inviter=inviter,
            invite_email_address=invite_email_address,
        )

    def create_permission(self, name="account"):
        return Permission.objects.create(**PERMISSIONS[name])

    def create_requirement(self, name="contract_nda"):
        return Requirement.objects.create(**REQUIREMENTS[name])

    def create_contract_template(self, name="nda"):
        return ContractTemplate.objects.create(**CONTRACT_TEMPLATES[name])

    def create_nationality(self, nationality="fi"):
        return Nationality.objects.create(**NATIONALITIES[nationality])

    def create_account(self, account_type=Account.Type.LIGHT, uid="1k234567", status=Account.Status.ENABLED):
        return Account.objects.create(identity=self.identity, type=account_type, uid=uid, status=status)

    def setUp(self):
        self.user = None
        self.superuser = None
        self.identity = None
        self.superidentity = None
        super().setUp()


class BaseTestCase(TestData):
    """
    TestCase class with test data.
    """

    def setUp(self):
        super().setUp()
        self.factory = RequestFactory()


class BaseAPITestCase(TestData, APITestCase):
    """
    APITestCase class with test data.
    """

    def setUp(self):
        super().setUp()
        self.factory = APIRequestFactory()
        self.url = "/api/v0/"
