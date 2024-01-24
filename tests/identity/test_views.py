"""
View tests for identity app.
"""

from unittest import mock
from unittest.mock import ANY, call

from django.contrib.admin.models import LogEntry
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.core import mail
from django.test import Client
from ldap import SIZELIMIT_EXCEEDED

from base.utils import set_default_permissions
from identity.models import (
    Contract,
    ContractTemplate,
    EmailAddress,
    Identifier,
    Identity,
    PhoneNumber,
)
from tests.setup import BaseTestCase


class MockLdapConn:
    def __init__(self, size_exceeded=False):
        self.size_exceeded = size_exceeded
        self.search_args = []

    LDAP_RETURN_VALUE = [
        (
            "uid=ldapuser,ou=users,dc=example,dc=org",
            {
                "uid": [b"ldapuser"],
                "cn": [b"Ldap User"],
                "mail": [b"ldap.user@example.org"],
            },
        )
    ]

    def search_s(self, *args, **kwargs):
        self.search_args.append(args)
        if self.size_exceeded:
            raise SIZELIMIT_EXCEEDED
        return self.LDAP_RETURN_VALUE


class IdentityTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.url = "/identity/"
        self.client = Client()
        set_default_permissions(self.user)
        self.client.force_login(self.user)

    def test_anonymous_view_redirects_to_login(self):
        client = Client()
        response = client.get(f"{self.url}1/")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login/", response["location"])

    def test_view_identity_without_identity(self):
        self.identity.delete()
        self.user.first_name = "Test"
        self.user.last_name = "User"
        self.user.email = "test.user@example.org"
        self.user.save()
        response = self.client.get(f"{self.url}me/", follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("New identity created.", response.content.decode("utf-8"))
        self.assertTrue(
            Identity.objects.filter(
                user=self.user, given_names="Test", surname="User", email_addresses__address="test.user@example.org"
            ).exists()
        )

    def test_view_identity(self):
        response = self.client.get(f"{self.url}{self.identity.pk}/")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("alert", response.content.decode("utf-8"))
        self.assertIn("Test User</h1>", response.content.decode("utf-8"))

    @mock.patch("base.connectors.ldap._get_connection")
    def test_search_identity(self, mock_ldap):
        mock_ldap.return_value = MockLdapConn()
        EmailAddress.objects.create(
            identity=self.superidentity,
            address="super@example.org",
        )
        url = f"{self.url}search/?given_names=test&email=super@example.org"
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Test User", response.content.decode("utf-8"))
        self.assertIn("Super User", response.content.decode("utf-8"))

    def test_search_identity_without_permission(self):
        set_default_permissions(self.user, remove=True)
        url = f"{self.url}search/?given_names=test&email=super@example.org"
        response = self.client.get(url)
        self.assertEqual(response.status_code, 403)

    @mock.patch("base.connectors.ldap.logger")
    def test_search_ldap_fail(self, mock_logger):
        url = f"{self.url}search/?uid=testuser"
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertIn("LDAP search failed", response.content.decode("utf-8"))
        mock_logger.error.assert_called_once()

    @mock.patch("base.connectors.ldap._get_connection")
    def test_search_ldap(self, mock_ldap):
        mock_ldap.return_value = MockLdapConn()
        url = f"{self.url}search/?uid=testuser&given_names=test"
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Test User", response.content.decode("utf-8"))
        self.assertEqual(response.content.decode("utf-8").count("ldap.user@example.org"), 1)

    @mock.patch("base.connectors.ldap._get_connection")
    def test_search_ldap_sizelimit_exceeded(self, mock_ldap):
        mock_ldap.return_value = MockLdapConn(size_exceeded=True)
        url = f"{self.url}search/?uid=testuser&given_names=test"
        response = self.client.get(url)
        self.assertIn("search returned too many results", response.content.decode("utf-8"))

    @mock.patch("base.connectors.ldap._get_connection")
    def test_search_ldap_escaping(self, mock_ldap):
        conn = MockLdapConn()
        mock_ldap.return_value = conn
        url = f"{self.url}search/?given_names=t*est"
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertIn("(givenName=*t\\2aest*)", conn.search_args[0][2])


class IdentityEditTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.url = "/identity/1/change/"
        self.client = Client()
        self.data = {
            "given_names": self.identity.given_names,
            "surname": self.identity.surname,
            "given_name_display": self.identity.given_name_display,
            "surname_display": self.identity.surname_display,
            "preferred_language": self.identity.preferred_language,
            "date_of_birth": "1999-01-01",
            "gender": self.identity.gender,
            "fpic": self.identity.fpic,
            "nationality": 1,
            "given_names_verification": self.identity.given_names_verification,
            "surname_verification": self.identity.surname_verification,
            "date_of_birth_verification": self.identity.date_of_birth_verification,
            "fpic_verification": self.identity.fpic_verification,
            "nationality_verification": self.identity.nationality_verification,
        }

    def test_edit_own_information_listed_fields(self):
        self.client.force_login(self.user)
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Basic information", response.content.decode("utf-8"))
        self.assertIn("Restricted information", response.content.decode("utf-8"))
        self.assertNotIn("verification method", response.content.decode("utf-8"))

    def test_edit_own_information_disabled_fields(self):
        self.identity.given_names_verification = 4
        self.identity.save()
        self.client.force_login(self.user)
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertIn('disabled id="id_given_names"', response.content.decode("utf-8"))

    def test_edit_own_information(self):
        self.client.force_login(self.user)
        response = self.client.post(self.url, self.data, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Test User</h1>", response.content.decode("utf-8"))
        self.assertIn("Jan. 1, 1999", response.content.decode("utf-8"))

    def test_edit_identity_view_with_superuser(self):
        self.client.force_login(self.superuser)
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Restricted information", response.content.decode("utf-8"))
        self.assertIn("verification method", response.content.decode("utf-8"))

    def test_edit_strong_electrical_verification_error(self):
        self.identity.given_names_verification = 4
        self.identity.save()
        self.data["given_names"] = "New Name"
        self.data["given_names_verification"] = 4
        self.client.force_login(self.superuser)
        response = self.client.post(self.url, self.data)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Cannot set strong electrical verification by hand", response.content.decode("utf-8"))

    def test_edit_other_user(self):
        self.identity.given_names_verification = 4
        self.identity.save()
        self.data["given_names"] = "New Name"
        self.data["given_names_verification"] = 3
        self.client.force_login(self.superuser)
        response = self.client.post(self.url, self.data)
        self.assertEqual(response.status_code, 302)


class ContactTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.url = f"/identity/{self.identity.pk}/contacts/"
        self.number = PhoneNumber.objects.create(
            identity=self.identity,
            number="+1234567890",
            priority=0,
        )
        self.client = Client()
        self.client.force_login(self.user)

    def test_view_contacts(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertIn("+1234567890", response.content.decode("utf-8"))
        self.assertIn("test@example.org", response.content.decode("utf-8"))

    def test_post_new_email_contact(self):
        data = {"contact": "test@example.com"}
        response = self.client.post(self.url, data, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("test@example.org", response.content.decode("utf-8"))
        self.assertIn("test@example.com</th>", response.content.decode("utf-8"))

    def test_post_new_phone_contact(self):
        data = {"contact": "+358123456789"}
        response = self.client.post(self.url, data, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("+1234567890</th>", response.content.decode("utf-8"))

    def test_post_incorrect_contact(self):
        data = {"contact": "incorrect"}
        response = self.client.post(self.url, data, follow=True)
        self.assertIn("Invalid e-mail address or phone number", response.content.decode("utf-8"))

    def test_post_contact_over_limit(self):
        data = {"contact": "test@example.com"}
        with self.settings(CONTACT_LIMIT=1):
            response = self.client.post(self.url, data, follow=True)
        self.assertIn("Maximum number of e-mail addresses reached", response.content.decode("utf-8"))

    def test_post_change_priority_up(self):
        new_number = PhoneNumber.objects.create(
            identity=self.identity,
            number="+3580123456789",
            priority=1,
        )
        data = {"phone_up": new_number.pk}
        self.client.post(self.url, data, follow=True)
        new_number.refresh_from_db()
        self.number.refresh_from_db()
        self.assertEqual(new_number.priority, 0)
        self.assertEqual(self.number.priority, 1)

    def test_post_change_priority_down(self):
        new_number = PhoneNumber.objects.create(
            identity=self.identity,
            number="+3580123456789",
            priority=1,
        )
        data = {"phone_down": self.number.pk}
        self.client.post(self.url, data, follow=True)
        new_number.refresh_from_db()
        self.number.refresh_from_db()
        self.assertEqual(new_number.priority, 0)
        self.assertEqual(self.number.priority, 1)

    def test_remove_phone(self):
        data = {"phone_remove": self.number.pk}
        response = self.client.post(self.url, data, follow=True)
        self.assertNotIn("+1234567890", response.content.decode("utf-8"))
        with self.assertRaises(PhoneNumber.DoesNotExist):
            self.number.refresh_from_db()


class IdentifierTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.url = f"/identity/{self.identity.pk}/identifiers/"
        self.identifier = Identifier.objects.create(
            identity=self.identity,
            type="eppn",
            value="identifier@example.org",
        )
        self.client = Client()
        self.client.force_login(self.user)

    def test_view_identifiers(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertIn("identifier@example.org", response.content.decode("utf-8"))

    def test_deactivate_identifier(self):
        Identifier.objects.create(
            identity=self.identity,
            type="eppn",
            value="identifier@example.com",
        )
        self.assertIsNone(self.identifier.deactivated_at)
        data = {"identifier_deactivate": self.identifier.pk}
        self.client.post(self.url, data, follow=True)
        self.identifier.refresh_from_db()
        self.assertIsNotNone(self.identifier.deactivated_at)

    def test_deactivate_last_identifier(self):
        self.assertIsNone(self.identifier.deactivated_at)
        data = {"identifier_deactivate": self.identifier.pk}
        response = self.client.post(self.url, data, follow=True)
        self.assertIn("Cannot deactivate", response.content.decode("utf-8"))
        self.identifier.refresh_from_db()
        self.assertIsNone(self.identifier.deactivated_at)

    def test_deactivate_identifier_with_another_user(self):
        user = get_user_model().objects.create_user(username="another")
        self.client.force_login(user)
        self.assertIsNone(self.identifier.deactivated_at)
        data = {"identifier_deactivate": self.identifier.pk}
        response = self.client.post(self.url, data, follow=True)
        self.assertIn("Permission denied", response.content.decode("utf-8"))
        self.identifier.refresh_from_db()
        self.assertIsNone(self.identifier.deactivated_at)


class VerificationTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.url = f"/email/{self.email_address.pk}/verify/"
        self.client = Client()
        self.client.force_login(self.user)

    def test_view_verification_page(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Verification code sent", response.content.decode("utf-8"))

    def test_verify_address(self):
        self.client.get(self.url)
        code = mail.outbox[0].body.split(" ")[-1]
        data = {"code": code}
        response = self.client.post(self.url, data, follow=True)
        self.assertIn("test@example.org", response.content.decode("utf-8"))
        self.assertIn("Verified", response.content.decode("utf-8"))
        self.email_address.refresh_from_db()
        self.assertTrue(self.email_address.verified)

    def test_verify_address_invalid_address(self):
        data = {"code": "invalid_code"}
        response = self.client.post(self.url, data, follow=True)
        self.assertIn("Invalid verification code", response.content.decode("utf-8"))

    @mock.patch("identity.views.SmsConnector")
    def test_verify_sms(self, mock_connector):
        number = PhoneNumber.objects.create(identity=self.identity, number="+1234567890", priority=0, verified=False)
        mock_connector.return_value.send_sms.return_value = True
        url = f"/phone/{number.pk}/verify/"
        self.client.get(url)
        code = mock_connector.return_value.send_sms.call_args.args[1].split(" ")[-1]
        data = {"code": code}
        self.client.post(url, data, follow=True)
        number.refresh_from_db()
        self.assertTrue(number.verified)


class AdminSiteTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.url = "/admin/identity/"
        self.client = Client()
        self.client.force_login(user=self.superuser)

    def test_view_admin_email_addresses(self):
        response = self.client.get(f"{self.url}emailaddress/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("test@example.org", response.content.decode("utf-8"))

    def test_view_admin_phone_numbers(self):
        PhoneNumber.objects.create(
            identity=self.identity,
            number="+358123456789",
        )
        response = self.client.get(f"{self.url}phonenumber/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("+358123456789", response.content.decode("utf-8"))

    def test_view_admin_identity(self):
        response = self.client.get(f"{self.url}identity/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Test Me", response.content.decode("utf-8"))

    def test_view_admin_identifier(self):
        response = self.client.get(f"{self.url}identifier/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("0 Identifiers", response.content.decode("utf-8"))


class ContractTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.contract_template = ContractTemplate.objects.create(
            type="testtemplate",
            version=1,
            name_en="Test Contract en",
            name_fi="Test Contract fi",
            name_sv="Test Contract sv",
            text_en="Test Content en",
            text_fi="Test Content fi",
            text_sv="Test Content sv",
        )
        self.client = Client()
        self.client.force_login(self.user)

    def _create_templates(self):
        self.contract_templates = [
            ContractTemplate.objects.create(
                type=f"testtemplate {i}",
                version=1,
                name_en=f"Test Contract en {i}",
                name_fi=f"Test Contract fi {i}",
                name_sv=f"Test Contract sv {i}",
                text_en=f"Test Content en {i}",
                text_fi=f"Test Content fi {i}",
                text_sv=f"Test Content sv {i}",
                public=bool(i % 2),
            )
            for i in range(2)
        ]

    def test_modify_contract_creates_new_version(self):
        self.contract_template.name_en = "New name"
        self.contract_template.save()
        self.assertTrue(ContractTemplate.objects.filter(type="testtemplate", version=2).exists())

    def test_contract_sign_page(self):
        response = self.client.get(f"/identity/{self.identity.pk}/contracts/{self.contract_template.pk}/sign/")
        self.assertIn(self.contract_template.name(), response.content.decode("utf-8"))
        self.assertIn(self.contract_template.text(), response.content.decode("utf-8"))
        self.assertIn(self.identity.display_name(), response.content.decode("utf-8"))

    @mock.patch("base.utils.logger_audit")
    def test_contract_sign_contract(self, mock_logger):
        response = self.client.post(
            f"/identity/{self.identity.pk}/contracts/{self.contract_template.pk}/sign/",
            {"sign_contract": self.contract_template.pk},
            follow=True,
        )
        self.assertTrue(Contract.objects.filter(identity=self.identity, template=self.contract_template).exists())
        self.assertIn("Contract signed", response.content.decode("utf-8"))
        self.assertIn(self.contract_template.name(), response.content.decode("utf-8"))
        self.assertEqual(
            LogEntry.objects.filter(
                change_message=f"Contract {self.contract_template.type}-{self.contract_template.version} signed."
            ).count(),
            1,
        )
        mock_logger.log.assert_has_calls(
            [
                call(
                    20, f"Contract {self.contract_template.type}-{self.contract_template.version} signed.", extra=ANY
                ),
            ]
        )
        self.assertEqual(
            mock_logger.log.call_args_list[0][1]["extra"]["contract_checksum"], Contract.objects.last().checksum
        )

    def test_contract_sign_old_version(self):
        template_pk = self.contract_template.pk
        self.test_modify_contract_creates_new_version()
        response = self.client.post(
            f"/identity/{self.identity.pk}/contracts/{template_pk}/sign/",
            {"sign_contract": template_pk},
            follow=True,
        )
        self.assertFalse(Contract.objects.filter(identity=self.identity, template=self.contract_template).exists())
        self.assertIn("Contract version has changed", response.content.decode("utf-8"))

    def test_view_contract_list(self):
        self._create_templates()
        contract = Contract.objects.sign_contract(
            identity=self.identity,
            template=self.contract_template,
        )
        super_contract = Contract.objects.sign_contract(
            identity=self.superidentity,
            template=self.contract_template,
        )
        response = self.client.get(f"/identity/{self.identity.pk}/contracts/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(contract.checksum, response.content.decode("utf-8"))
        self.assertNotIn(super_contract.checksum, response.content.decode("utf-8"))
        self.assertNotIn(self.contract_templates[0].name(), response.content.decode("utf-8"))
        self.assertIn(self.contract_templates[1].name(), response.content.decode("utf-8"))

    def test_view_contract(self):
        self._create_templates()
        contract = Contract.objects.sign_contract(
            identity=self.identity,
            template=self.contract_template,
        )
        super_contract = Contract.objects.sign_contract(
            identity=self.superidentity,
            template=self.contract_template,
        )
        response = self.client.get(f"/contract/{contract.pk}/")
        self.assertEqual(response.status_code, 200)
        response = self.client.get(f"/contract/{super_contract.pk}/")
        self.assertEqual(response.status_code, 404)
        content_type = ContentType.objects.get(app_label="identity", model="identity")
        permission = Permission.objects.get(content_type=content_type, codename="view_contracts")
        self.user.user_permissions.add(permission)
        self.client.force_login(self.user)
        response = self.client.get(f"/contract/{super_contract.pk}/")
        self.assertEqual(response.status_code, 200)

    def test_view_contracts_list_only_latest(self):
        self._create_templates()
        contract = Contract.objects.sign_contract(
            identity=self.identity,
            template=self.contract_template,
        )
        self.contract_template.save()
        contract2 = Contract.objects.sign_contract(
            identity=self.identity,
            template=self.contract_template,
        )
        response = self.client.get(f"/identity/{self.identity.pk}/contracts/")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(contract.checksum, response.content.decode("utf-8"))
        self.assertIn(contract2.checksum, response.content.decode("utf-8"))

    def test_view_contracts_list_all(self):
        self._create_templates()
        contract = Contract.objects.sign_contract(
            identity=self.identity,
            template=self.contract_template,
        )
        self.contract_template.save()
        contract2 = Contract.objects.sign_contract(
            identity=self.identity,
            template=self.contract_template,
        )
        response = self.client.get(f"/identity/{self.identity.pk}/contracts/?list_all=1")
        self.assertEqual(response.status_code, 200)
        self.assertIn(contract.checksum, response.content.decode("utf-8"))
        self.assertIn(contract2.checksum, response.content.decode("utf-8"))

    def test_validate_contract(self):
        from uuid import uuid4

        self._create_templates()
        contract = Contract.objects.sign_contract(
            identity=self.identity,
            template=self.contract_template,
        )
        self.assertTrue(contract.validate())
        kamu_id = contract.identity.kamu_id
        contract.identity.kamu_id = uuid4()
        contract.identity.save()
        self.assertFalse(contract.validate())
        Identifier.objects.create(identity=contract.identity, type="kamu", value=kamu_id)
        self.assertTrue(contract.validate())
