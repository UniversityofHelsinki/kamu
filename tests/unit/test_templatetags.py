"""
Unit tests for template tags
"""

from django.test import override_settings

from kamu.templatetags.account_tags import manage_link
from kamu.templatetags.identity_tags import (
    matching_attributes,
    matching_attributes_ldap,
)
from tests.setup import TestData


class MatchingAttributeTests(TestData):
    def setUp(self):
        super().setUp()
        self.create_identity(user=False, email=True, phone=True)

    @override_settings(PUBLIC_EMAIL_DOMAINS=["example.com"])
    def test_no_matching_attributes(self):
        attributes = matching_attributes(self.identity)
        self.assertEqual(attributes, "")

    @override_settings(PUBLIC_EMAIL_DOMAINS=["example.org"])
    def test_public_email_domain(self):
        attributes = matching_attributes(self.identity)
        self.assertEqual(attributes, "test@example.org")

    @override_settings(PUBLIC_EMAIL_DOMAINS=["example.org"])
    def test_matching_attributes(self):
        attributes = matching_attributes(
            self.identity, email=self.email_address.address, phone=self.phone_number.number
        )
        self.assertEqual(attributes, "<b>test@example.org</b>, <b>+1234567890</b>")

    @override_settings(PUBLIC_EMAIL_DOMAINS=["example.org"])
    @override_settings(ALLOW_TEST_FPIC=True)
    def test_matching_fpic(self):
        self.identity.fpic = "010181-900C"
        self.identity.save()
        attributes = matching_attributes(self.identity, fpic="010181-900C")
        self.assertEqual(attributes, "test@example.org, <b>010181-900C</b>")


class MatchingAttributeLdapTests(TestData):
    def setUp(self):
        super().setUp()
        self.ldap_result = {
            "mail": "test@example.org",
            "schacPersonalUniqueID": "urn:schac:personalUniqueID:fi:FIC:010181-900C",
        }

    @override_settings(PUBLIC_EMAIL_DOMAINS=["example.com"])
    def test_no_matching_attributes(self):
        attributes = matching_attributes_ldap(self.ldap_result)
        self.assertEqual(attributes, "")

    @override_settings(PUBLIC_EMAIL_DOMAINS=["example.org"])
    def test_public_email_domain(self):
        attributes = matching_attributes_ldap(self.ldap_result)
        self.assertEqual(attributes, "test@example.org")

    @override_settings(PUBLIC_EMAIL_DOMAINS=["example.org"])
    @override_settings(ALLOW_TEST_FPIC=True)
    def test_matching_attributes(self):
        attributes = matching_attributes_ldap(self.ldap_result, email="test@example.org", fpic="010181-900C")
        self.assertEqual(attributes, "<b>test@example.org</b>, <b>010181-900C</b>")


class AccountManageLinkTests(TestData):
    def setUp(self):
        super().setUp()
        self.identity = self.create_identity()
        self.account = self.create_account()

    @override_settings(ACCOUNT_ACTIONS={})
    def test_create_unknown_type(self):
        link = manage_link(self.account)
        self.assertEqual(link, "")

    @override_settings(ACCOUNT_ACTIONS={"lightaccount": "create"})
    def test_create_link(self):
        link = manage_link(self.account)
        self.assertEqual(link, '<a href="/account/1/" class="btn btn-primary mb-2">Manage account</a>')

    @override_settings(ACCOUNT_ACTIONS={"lightaccount": "https://localhost/manage"})
    def test_create_external_link(self):
        link = manage_link(self.account)
        self.assertEqual(
            link,
            '<a href="https://localhost/manage" class="btn btn-primary mb-2" target="_blank" rel="noopener">'
            "Manage in external service</a>",
        )
