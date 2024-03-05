"""
View tests for identities.
"""

import datetime
from unittest import mock
from unittest.mock import ANY, call

from django.contrib.admin.models import LogEntry
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission, User
from django.contrib.contenttypes.models import ContentType
from django.core import mail
from django.test import Client, override_settings
from django.utils import timezone

from kamu.models.contract import Contract, ContractTemplate
from kamu.models.identity import EmailAddress, Identifier, Identity, PhoneNumber
from kamu.models.membership import Membership
from kamu.models.role import Role
from kamu.utils.auth import set_default_permissions
from tests.setup import BaseTestCase
from tests.utils import MockLdapConn


class IdentityTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.create_user()
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
        self.user.email = "test.user@example.org"
        self.user.save()
        response = self.client.get(f"{self.url}me/", follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("New identity created.", response.content.decode("utf-8"))
        self.assertTrue(
            Identity.objects.filter(
                user=self.user,
                given_names=self.user.first_name,
                surname=self.user.last_name,
                email_addresses__address=self.user.email,
            ).exists()
        )

    @mock.patch("kamu.utils.audit.logger_audit")
    def test_view_identity(self, mock_logger):
        self.create_identity()
        response = self.client.get(f"{self.url}{self.identity.pk}/")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("alert", response.content.decode("utf-8"))
        self.assertIn(f"{self.identity.display_name()}</h1>", response.content.decode("utf-8"))
        mock_logger.log.assert_has_calls(
            [
                call(20, "Read identity information", extra=ANY),
            ]
        )

    @mock.patch("kamu.connectors.ldap._get_connection")
    @mock.patch("kamu.utils.audit.logger_audit")
    def test_search_identity(self, mock_logger, mock_ldap):
        self.create_identity(email=True)
        self.create_superidentity(email=True)
        mock_ldap.return_value = MockLdapConn(limited_fields=True)
        data = {"given_names": "test", "email": "super_test@example.org"}
        url = f"{self.url}search/"
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, 200)
        self.assertIn(self.identity.display_name(), response.content.decode("utf-8"))
        self.assertIn(self.superidentity.display_name(), response.content.decode("utf-8"))
        mock_logger.log.assert_has_calls(
            [
                call(20, "Searched identities", extra=ANY),
            ]
        )
        self.assertEqual(
            mock_logger.log.call_args_list[0][1]["extra"]["search_terms"],
            str({"given_names": "test", "email": "super_test@example.org"}),
        )

    def test_search_identity_without_permission(self):
        set_default_permissions(self.user, remove=True)
        data = {"given_names": "test", "email": "super@example.org"}
        url = f"{self.url}search"
        response = self.client.post(url, data, follow=True)
        self.assertEqual(response.status_code, 403)

    def test_search_form_help_text(self):
        url = f"{self.url}search/"
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertIn(
            "Name search returns partial matches from Kamu.",
            response.content.decode("utf-8"),
        )
        self.assertNotIn(
            "user directory",
            response.content.decode("utf-8"),
        )


class IdentityEditTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.create_identity(user=True)
        self.nationality = self.create_nationality("fi")
        self.url = f"/identity/{self.identity.pk}/change/"
        self.client = Client()
        self.data = {
            "given_names": self.identity.given_names,
            "surname": self.identity.surname,
            "given_name_display": self.identity.given_name_display,
            "surname_display": self.identity.surname_display,
            "preferred_language": self.identity.preferred_language,
            "date_of_birth": "1999-01-01",
            "gender": self.identity.gender,
            "nationality": self.nationality.pk,
            "given_names_verification": self.identity.given_names_verification,
            "surname_verification": self.identity.surname_verification,
            "date_of_birth_verification": self.identity.date_of_birth_verification,
            "nationality_verification": self.identity.nationality_verification,
            "fpic_verification": self.identity.fpic_verification,
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

    @override_settings(ALLOW_TEST_FPIC=True)
    @mock.patch("kamu.utils.audit.logger_audit")
    def test_edit_own_information(self, mock_logger):
        self.client.force_login(self.user)
        self.identity.surname_verification = Identity.VerificationMethod.EXTERNAL
        self.identity.save()
        self.data["surname"] = "New-User"
        self.data["fpic"] = "010181-900C"
        response = self.client.post(self.url, self.data, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(f"{self.identity.display_name()}</h1>", response.content.decode("utf-8"))
        self.assertIn("New-User", response.content.decode("utf-8"))
        self.assertIn("Jan. 1, 1999", response.content.decode("utf-8"))
        self.assertIn("010181-900C", response.content.decode("utf-8"))
        self.identity.refresh_from_db()
        self.assertEqual(self.identity.fpic_verification, Identity.VerificationMethod.SELF_ASSURED)
        self.assertEqual(self.identity.surname_verification, Identity.VerificationMethod.SELF_ASSURED)
        mock_logger.log.assert_has_calls(
            [
                call(20, "Changed identity information", extra=ANY),
            ]
        )

    def test_edit_identity_view_with_superuser(self):
        self.create_superuser()
        self.client.force_login(self.superuser)
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Restricted information", response.content.decode("utf-8"))
        self.assertIn("verification method", response.content.decode("utf-8"))

    def test_edit_strong_electrical_verification_error(self):
        self.create_superuser()
        self.identity.given_names_verification = Identity.VerificationMethod.STRONG
        self.identity.save()
        self.data["given_names"] = "New Name"
        self.data["given_names_verification"] = Identity.VerificationMethod.STRONG
        self.client.force_login(self.superuser)
        response = self.client.post(self.url, self.data)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Cannot set strong electrical verification by hand", response.content.decode("utf-8"))

    def test_edit_lower_verification_level(self):
        self.create_superuser()
        self.identity.given_names_verification = Identity.VerificationMethod.STRONG
        self.identity.save()
        self.data["given_names"] = "New Name"
        self.data["given_names_verification"] = Identity.VerificationMethod.PHOTO_ID
        self.client.force_login(self.superuser)
        response = self.client.post(self.url, self.data)
        self.assertEqual(response.status_code, 302)


class ContactTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.create_identity(user=True, email=True, phone=True)
        self.url = f"/identity/{self.identity.pk}/contacts/"
        self.client = Client()
        self.client.force_login(self.user)

    @mock.patch("kamu.utils.audit.logger_audit")
    def test_view_contacts(self, mock_logger):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertIn(self.phone_number.number, response.content.decode("utf-8"))
        self.assertIn(self.email_address.address, response.content.decode("utf-8"))
        mock_logger.log.assert_has_calls(
            [
                call(20, "Listed contact information", extra=ANY),
            ]
        )

    @mock.patch("kamu.utils.audit.logger_audit")
    def test_post_new_email_contact(self, mock_logger):
        data = {"contact": "test@example.com"}
        response = self.client.post(self.url, data, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(self.email_address.address, response.content.decode("utf-8"))
        self.assertIn("test@example.com</th>", response.content.decode("utf-8"))
        mock_logger.log.assert_has_calls(
            [
                call(20, "Added email address", extra=ANY),
            ]
        )

    @mock.patch("kamu.utils.audit.logger_audit")
    def test_post_new_phone_contact(self, mock_logger):
        data = {"contact": "+358123456789"}
        response = self.client.post(self.url, data, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("+358123456789</th>", response.content.decode("utf-8"))
        mock_logger.log.assert_has_calls(
            [
                call(20, "Added phone number", extra=ANY),
            ]
        )
        self.assertEqual(LogEntry.objects.filter(change_message="Added phone number").count(), 1)

    def test_post_incorrect_contact(self):
        data = {"contact": "incorrect"}
        response = self.client.post(self.url, data, follow=True)
        self.assertIn("Phone number must start with a plus sign", response.content.decode("utf-8"))

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
        self.phone_number.refresh_from_db()
        self.assertEqual(new_number.priority, 0)
        self.assertEqual(self.phone_number.priority, 1)

    def test_post_change_priority_down(self):
        new_number = PhoneNumber.objects.create(
            identity=self.identity,
            number="+3580123456789",
            priority=1,
        )
        data = {"phone_down": self.phone_number.pk}
        self.client.post(self.url, data, follow=True)
        new_number.refresh_from_db()
        self.phone_number.refresh_from_db()
        self.assertEqual(new_number.priority, 0)
        self.assertEqual(self.phone_number.priority, 1)

    @mock.patch("kamu.utils.audit.logger_audit")
    def test_remove_phone(self, mock_logger):
        data = {"phone_remove": self.phone_number.pk}
        response = self.client.post(self.url, data, follow=True)
        self.assertNotIn("+1234567890", response.content.decode("utf-8"))
        with self.assertRaises(PhoneNumber.DoesNotExist):
            self.phone_number.refresh_from_db()
        mock_logger.log.assert_has_calls(
            [
                call(20, "Deleted phone number", extra=ANY),
            ]
        )


class IdentifierTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.create_identity(user=True)
        self.url = f"/identity/{self.identity.pk}/identifiers/"
        self.identifier = Identifier.objects.create(
            identity=self.identity,
            type=Identifier.Type.EPPN,
            value="identifier@example.org",
        )
        self.client = Client()
        self.client.force_login(self.user)

    @mock.patch("kamu.utils.audit.logger_audit")
    def test_view_identifiers(self, mock_logger):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertIn("identifier@example.org", response.content.decode("utf-8"))
        mock_logger.log.assert_has_calls(
            [
                call(20, "Listed identifier information", extra=ANY),
            ]
        )

    @mock.patch("kamu.utils.audit.logger_audit")
    def test_deactivate_identifier(self, mock_logger):
        Identifier.objects.create(
            identity=self.identity,
            type=Identifier.Type.EPPN,
            value="identifier@example.com",
        )
        self.assertIsNone(self.identifier.deactivated_at)
        data = {"identifier_deactivate": self.identifier.pk}
        self.client.post(self.url, data, follow=True)
        self.identifier.refresh_from_db()
        self.assertIsNotNone(self.identifier.deactivated_at)
        mock_logger.log.assert_has_calls(
            [
                call(20, "Deactivated identifier", extra=ANY),
            ]
        )

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
        self.create_identity(user=True, email=True, phone=True)
        self.email_address.verified = False
        self.email_address.save()
        self.phone_number.verified = False
        self.phone_number.save()
        self.url = f"/email/{self.email_address.pk}/verify/"
        self.client = Client()
        self.client.force_login(self.user)

    def test_view_verification_page(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Verification code sent", response.content.decode("utf-8"))

    def _verify_address(self):
        self.client.get(self.url)
        code = mail.outbox[0].body.split(" ")[-1]
        data = {"code": code}
        return self.client.post(self.url, data, follow=True)

    @mock.patch("kamu.utils.audit.logger_audit")
    def test_verify_address(self, mock_logger):
        response = self._verify_address()
        self.assertIn(self.email_address.address, response.content.decode("utf-8"))
        self.assertIn("Verified", response.content.decode("utf-8"))
        self.email_address.refresh_from_db()
        self.assertTrue(self.email_address.verified)
        mock_logger.log.assert_has_calls(
            [
                call(20, "Verified email address", extra=ANY),
            ]
        )

    @mock.patch("kamu.utils.audit.logger_audit")
    def test_verify_already_verified_address(self, mock_logger):
        self.create_superidentity()
        email = EmailAddress.objects.create(
            identity=self.superidentity, address=self.email_address.address, verified=True
        )
        self._verify_address()
        self.email_address.refresh_from_db()
        self.assertTrue(self.email_address.verified)
        email.refresh_from_db()
        self.assertFalse(email.verified)
        mock_logger.log.assert_has_calls(
            [
                call(20, "Verified email address", extra=ANY),
                call(
                    30, "Removed verification from the email address as the address was verified elsewhere", extra=ANY
                ),
            ]
        )
        self.assertTrue(
            LogEntry.objects.filter(
                change_message="Verified email address", object_id=str(self.email_address.pk)
            ).exists()
        )
        self.assertTrue(
            LogEntry.objects.filter(
                change_message="Removed verification from the email address as the address was verified elsewhere",
                object_id=str(email.pk),
            ).exists()
        )

    def test_verify_address_invalid_address(self):
        data = {"code": "invalid_code"}
        response = self.client.post(self.url, data, follow=True)
        self.assertIn("Invalid verification code", response.content.decode("utf-8"))

    def _verify_sms(self, mock_connector, number):
        mock_connector.return_value.send_sms.return_value = True
        url = f"/phone/{number.pk}/verify/"
        self.client.get(url)
        code = mock_connector.return_value.send_sms.call_args.args[1].split(" ")[-1]
        data = {"code": code}
        self.client.post(url, data, follow=True)

    @mock.patch("kamu.views.identity.SmsConnector")
    @mock.patch("kamu.utils.audit.logger_audit")
    def test_verify_sms(self, mock_logger, mock_connector):
        self._verify_sms(mock_connector, self.phone_number)
        self.phone_number.refresh_from_db()
        self.assertTrue(self.phone_number.verified)
        mock_logger.log.assert_has_calls(
            [
                call(20, "Verified phone number", extra=ANY),
            ]
        )

    @mock.patch("kamu.views.identity.SmsConnector")
    @mock.patch("kamu.utils.audit.logger_audit")
    def test_verify_existing_sms(self, mock_logger, mock_connector):
        self.create_superidentity()
        verified_number = PhoneNumber.objects.create(
            identity=self.superidentity, number=self.phone_number.number, verified=True
        )
        self._verify_sms(mock_connector, self.phone_number)
        verified_number.refresh_from_db()
        self.assertFalse(verified_number.verified)
        self.phone_number.refresh_from_db()
        self.assertTrue(self.phone_number.verified)
        mock_logger.log.assert_has_calls(
            [
                call(20, "Verified phone number", extra=ANY),
                call(30, "Removed verification from the phone number as the number was verified elsewhere", extra=ANY),
            ]
        )


class ContractTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.create_identity(user=True)
        self.contract_template = self.create_contract_template("nda")
        self.client = Client()
        self.client.force_login(self.user)

    def test_modify_contract_creates_new_version(self):
        self.contract_template.name_en = "New name"
        self.contract_template.save()
        self.assertTrue(ContractTemplate.objects.filter(type=self.contract_template.type, version=2).exists())

    def test_contract_sign_page(self):
        response = self.client.get(f"/identity/{self.identity.pk}/contracts/{self.contract_template.pk}/sign/")
        self.assertIn(self.contract_template.name(), response.content.decode("utf-8"))
        self.assertIn(self.contract_template.text(), response.content.decode("utf-8"))
        self.assertIn(self.identity.display_name(), response.content.decode("utf-8"))

    @mock.patch("kamu.utils.audit.logger_audit")
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
                change_message=f"Contract {self.contract_template.type}-{self.contract_template.version} signed"
            ).count(),
            1,
        )
        mock_logger.log.assert_has_calls(
            [
                call(20, f"Contract {self.contract_template.type}-{self.contract_template.version} signed", extra=ANY),
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

    @mock.patch("kamu.utils.audit.logger_audit")
    def test_view_contract_list(self, mock_logger):
        self.create_superidentity()
        contract_template_public = self.create_contract_template("textcontract")
        contract_template_secret = self.create_contract_template("secretcontract")
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
        self.assertNotIn(contract_template_secret.name(), response.content.decode("utf-8"))
        self.assertIn(contract_template_public.name(), response.content.decode("utf-8"))
        mock_logger.log.assert_has_calls(
            [
                call(20, "Listed contract information", extra=ANY),
            ]
        )

    def test_view_signable_contract_list(self):
        self.create_superidentity()
        self.client.force_login(self.superuser)
        contract_template_public = self.create_contract_template("textcontract")
        response = self.client.get(f"/identity/{self.superidentity.pk}/contracts/")
        self.assertIn("Signable contracts", response.content.decode("utf-8"))
        self.assertIn(contract_template_public.name(), response.content.decode("utf-8"))
        response = self.client.get(f"/identity/{self.identity.pk}/contracts/")
        self.assertNotIn("Signable contracts", response.content.decode("utf-8"))
        self.assertNotIn(contract_template_public.name(), response.content.decode("utf-8"))

    @mock.patch("kamu.utils.audit.logger_audit")
    def test_view_contract(self, mock_logger):
        self.create_superidentity()
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
        mock_logger.log.assert_has_calls(
            [
                call(20, "Read contract information", extra=ANY),
            ]
        )
        response = self.client.get(f"/contract/{super_contract.pk}/")
        self.assertEqual(response.status_code, 404)
        content_type = ContentType.objects.get(app_label="kamu", model="identity")
        permission = Permission.objects.get(content_type=content_type, codename="view_contracts")
        self.user.user_permissions.add(permission)
        self.client.force_login(self.user)
        response = self.client.get(f"/contract/{super_contract.pk}/")
        self.assertEqual(response.status_code, 200)

    def test_view_contracts_list_only_latest(self):
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

        contract = Contract.objects.sign_contract(
            identity=self.identity,
            template=self.contract_template,
        )
        self.assertTrue(contract.validate())
        kamu_id = contract.identity.kamu_id
        contract.identity.kamu_id = uuid4()
        contract.identity.save()
        self.assertFalse(contract.validate())
        Identifier.objects.create(identity=contract.identity, type=Identifier.Type.KAMU, value=kamu_id)
        self.assertTrue(contract.validate())


class IdentityCombineTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.create_identity(user=True)
        self.create_superidentity(user=True)
        self.role = self.create_role()
        self.client = Client()
        self.client.force_login(self.superuser)
        self.url = f"/identity/combine/{self.superidentity.pk}/{self.identity.pk}/"
        self.data = {
            "combine": True,
            "primary_identity": self.superidentity.pk,
            "secondary_identity": self.identity.pk,
        }

    def _create_test_data(self):
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
            for i in range(4)
        ]
        Contract.objects.sign_contract(identity=self.identity, template=self.contract_templates[0])
        Contract.objects.sign_contract(identity=self.identity, template=self.contract_templates[1])
        Contract.objects.sign_contract(identity=self.superidentity, template=self.contract_templates[2])
        PhoneNumber.objects.create(identity=self.identity, number="+358123456789")
        PhoneNumber.objects.create(identity=self.identity, number="+358012345678")
        PhoneNumber.objects.create(identity=self.superidentity, number="+358001234567")
        EmailAddress.objects.create(identity=self.identity, address="test1@example.org", verified=True)
        EmailAddress.objects.create(identity=self.superidentity, address="supertest@example.org")
        EmailAddress.objects.create(identity=self.superidentity, address="test2@example.org")
        Identifier.objects.create(identity=self.identity, type=Identifier.Type.EPPN, value="test2@example.org")
        Identifier.objects.create(identity=self.superidentity, type=Identifier.Type.EPPN, value="super@example.org")
        role2 = Role.objects.create(identifier="anotherrole", name_en="Another Role", maximum_duration=10)
        Membership.objects.create(
            role=self.role,
            identity=self.superidentity,
            reason="Because",
            start_date=timezone.now().date(),
            expire_date=timezone.now().date() + datetime.timedelta(days=1),
        )
        Membership.objects.create(
            role=role2,
            identity=self.identity,
            reason="Because",
            start_date=timezone.now().date() + datetime.timedelta(days=1),
            expire_date=timezone.now().date() + datetime.timedelta(days=2),
        )
        Membership.objects.create(
            role=self.role,
            identity=self.superidentity,
            reason="Because",
            start_date=timezone.now().date(),
            expire_date=timezone.now().date() + datetime.timedelta(days=5),
        )

    def test_view_combine_identities_without_access(self):
        self.client.force_login(self.user)
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 403)

    def test_view_combine_selection(self):
        self.client.force_login(self.superuser)
        self.client.post(f"/identity/{self.identity.pk}/", {"combine_source": True})
        response = self.client.post(f"/identity/{self.superidentity.pk}/", {"combine_target": True})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, f"/identity/combine/{self.superidentity.pk}/{self.identity.pk}/")

    @mock.patch("kamu.utils.audit.logger_audit")
    def test_view_combine_identities(self, mock_logger):
        self._create_test_data()
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertIn(
            "Transfer information from the source identity to the target identity", response.content.decode("utf-8")
        )
        mock_logger.log.assert_has_calls(
            [
                call(20, "Read identity information", extra=ANY),
                call(20, "Read identity information", extra=ANY),
            ],
        )

    @mock.patch("kamu.utils.audit.logger_audit")
    def test_combine_identities(self, mock_logger):
        self._create_test_data()
        self.identity.date_of_birth = datetime.date(1999, 1, 1)
        self.identity.gender = Identity.Gender.OTHER
        self.identity.uid = "testuid"
        self.identity.save()
        kamu_id = self.identity.kamu_id
        response = self.client.post(self.url, self.data, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Identities combined.", response.content.decode("utf-8"))
        self.superidentity.refresh_from_db()
        self.assertEqual(self.superidentity.given_names, "Dr. Super")
        self.assertEqual(self.superidentity.gender, Identity.Gender.OTHER)
        self.assertEqual(self.superidentity.date_of_birth, datetime.date(1999, 1, 1))
        self.assertEqual(self.superidentity.membership_set.all().count(), 3)
        self.assertEqual(self.superidentity.phone_numbers.all().count(), 3)
        self.assertEqual(self.superidentity.email_addresses.all().count(), 3)
        self.assertEqual(self.superidentity.contracts.all().count(), 3)
        self.assertEqual(self.superidentity.identifiers.all().count(), 3)
        self.assertTrue(
            Identifier.objects.filter(identity=self.superidentity, type=Identifier.Type.KAMU, value=kamu_id).exists()
        )
        with self.assertRaises(Identity.DoesNotExist):
            self.identity.refresh_from_db()
        with self.assertRaises(User.DoesNotExist):
            self.user.refresh_from_db()
        mock_logger.log.assert_has_calls(
            [
                call(20, f"Identity transfer: membership from identity: {self.identity.pk}", extra=ANY),
                call(20, f"Identity transfer: contract from identity: {self.identity.pk}", extra=ANY),
                call(20, f"Identity transfer: phone_number from identity: {self.identity.pk}", extra=ANY),
                call(20, f"Identity transfer: email_address from identity: {self.identity.pk}", extra=ANY),
                call(20, f"Identity transfer: identifier from identity: {self.identity.pk}", extra=ANY),
                call(20, f"Identity transfer: gender from identity: {self.identity.pk}", extra=ANY),
                call(20, f"Identity transfer: date_of_birth from identity: {self.identity.pk}", extra=ANY),
                call(20, "User removed", extra=ANY),
                call(20, "Identity removed", extra=ANY),
            ],
            any_order=True,
        )

    @mock.patch("kamu.utils.audit.logger_audit")
    def test_combine_identities_identity_names(self, mock_logger):
        self.superidentity.given_names = ""
        self.superidentity.surname = ""
        self.superidentity.save()
        self.client.post(self.url, self.data)
        self.superidentity.refresh_from_db()
        self.assertEqual(self.superidentity.given_names, self.identity.given_names)
        self.assertEqual(self.superidentity.surname, self.identity.surname)
        mock_logger.log.assert_has_calls(
            [
                call(20, f"Identity transfer: given_names from identity: {self.identity.pk}", extra=ANY),
                call(20, f"Identity transfer: surname from identity: {self.identity.pk}", extra=ANY),
            ],
            any_order=True,
        )

    def test_combine_invalid_higher_assurance_level(self):
        self.identity.assurance_level = Identity.AssuranceLevel.HIGH
        self.identity.save()
        response = self.client.post(self.url, self.data, follow=True)
        self.assertIn(
            "Source identity cannot have higher assurance level than target.", response.content.decode("utf-8")
        )

    def test_combine_invalid_to_current_user(self):
        url = f"/identity/combine/{self.identity.pk}/{self.superidentity.pk}/"
        data = {
            "combine": True,
            "primary_identity": self.identity.pk,
            "secondary_identity": self.superidentity.pk,
        }
        response = self.client.post(url, data, follow=True)
        self.assertIn("cannot be the source identity", response.content.decode("utf-8"))

    def test_combine_invalid_primary_keys(self):
        data = {
            "combine": True,
            "primary_identity": self.identity.pk,
            "secondary_identity": self.superidentity.pk,
        }
        response = self.client.post(self.url, data, follow=True)
        self.assertIn("Incorrect primary keys", response.content.decode("utf-8"))

    def test_combine_two_uid(self):
        self.identity.uid = "test"
        self.identity.save()
        self.superidentity.uid = "super"
        self.superidentity.save()
        response = self.client.post(self.url, self.data, follow=True)
        self.assertIn("Cannot combine two identities with uid", response.content.decode("utf-8"))

    @override_settings(ALLOW_TEST_FPIC=True)
    def test_combine_two_fpic(self):
        self.identity.fpic = "010181-900C"
        self.identity.save()
        self.superidentity.fpic = "010866-9260"
        self.superidentity.save()
        response = self.client.post(self.url, self.data, follow=True)
        self.assertIn(
            "Cannot combine two identities with Finnish Personal Identity Code", response.content.decode("utf-8")
        )
