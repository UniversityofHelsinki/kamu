"""
View tests for identities.
"""

import datetime
import json
from unittest import mock
from unittest.mock import ANY, call

from django.contrib.admin.models import LogEntry
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission, User
from django.contrib.contenttypes.models import ContentType
from django.core import mail
from django.test import Client, override_settings
from django.utils import timezone
from requests import Response

from kamu.models.contract import Contract, ContractTemplate
from kamu.models.identity import (
    EmailAddress,
    Identifier,
    Identity,
    Nationality,
    PhoneNumber,
)
from kamu.models.membership import Membership
from kamu.models.role import Role
from kamu.utils.auth import set_default_permissions
from tests.setup import BaseTestCase


class IdentityViewTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.create_user()
        self.url = "/identity/"
        self.client = Client()

    def _login_user(self, permissions=True):
        if permissions:
            set_default_permissions(self.user)
        self.client.force_login(self.user)

    def test_anonymous_view_redirects_to_login(self):
        client = Client()
        response = client.get(f"{self.url}1/")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login/", response["location"])

    def test_view_identity_without_identity(self):
        self._login_user()
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
    def test_view_own_identity(self, mock_logger):
        self._login_user()
        self.create_identity()
        response = self.client.get(f"{self.url}{self.identity.pk}/")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("alert", response.content.decode("utf-8"))
        self.assertIn(f"{self.identity.display_name()} |", response.content.decode("utf-8"))
        mock_logger.log.assert_has_calls(
            [
                call(20, "Read identity information", extra=ANY),
            ]
        )

    @mock.patch("kamu.utils.audit.logger_audit")
    def test_view_other_identity(self, mock_logger):
        self._login_user()
        self.create_superidentity()
        response = self.client.get(f"{self.url}{self.superidentity.pk}/")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("alert", response.content.decode("utf-8"))
        self.assertIn(f"{self.superidentity.display_name()} |", response.content.decode("utf-8"))
        mock_logger.log.assert_has_calls(
            [
                call(20, "Read identity information", extra=ANY),
            ]
        )

    def test_view_identity_without_default_permissions(self):
        self._login_user(permissions=False)
        self.create_superidentity()
        response = self.client.get(f"{self.url}{self.superidentity.pk}/")
        self.assertEqual(response.status_code, 404)

    def test_view_identity_list_memberships(self):
        self._login_user()
        self.create_identity()
        role = self.create_role()
        self.create_membership(
            role,
            self.identity,
            start_delta_days=0,
            expire_delta_days=1,
        )
        response = self.client.get(f"{self.url}{self.identity.pk}/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Current and upcoming memberships", response.content.decode("utf-8"))
        self.assertNotIn("Expired memberships", response.content.decode("utf-8"))
        self.assertIn(role.name(), response.content.decode("utf-8"))

    def test_view_identity_list_expired_memberships(self):
        self._login_user()
        self.create_identity()
        role = self.create_role()
        self.create_membership(
            role,
            self.identity,
            start_delta_days=-2,
            expire_delta_days=-1,
        )
        response = self.client.get(f"{self.url}{self.identity.pk}/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("You do not have any current or upcoming memberships.", response.content.decode("utf-8"))
        self.assertIn("Expired memberships", response.content.decode("utf-8"))
        self.assertIn(role.name(), response.content.decode("utf-8"))


class IdentitySearchTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.create_user()
        self.url = "/identity/search/"
        self.client = Client()
        set_default_permissions(self.user)
        self.client.force_login(self.user)

    @mock.patch("kamu.utils.audit.logger_audit")
    @override_settings(SKIP_NAME_SEARCH_IF_IDENTIFIER_MATCHES=False)
    def test_search_identity(self, mock_logger):
        self.create_identity(email=True)
        self.create_superidentity(email=True)
        data = {"given_names": "test", "identifier": "super_test@example.org"}
        response = self.client.post(self.url, data)
        self.assertEqual(response.status_code, 200)
        self.assertIn(self.identity.display_name(), response.content.decode("utf-8"))
        self.assertIn(self.superidentity.display_name(), response.content.decode("utf-8"))
        self.assertIn("combined into a single list", response.content.decode("utf-8"))
        mock_logger.log.assert_has_calls(
            [
                call(20, "Searched identities", extra=ANY),
            ]
        )
        self.assertEqual(
            str({"given_names": "test", "email": "super_test@example.org"}),
            mock_logger.log.call_args_list[0][1]["extra"]["search_terms"],
        )

    def test_search_identity_skip_name_search_if_match_found(self):
        self.create_identity(email=True)
        self.create_superidentity(email=True)
        data = {"given_names": "test", "identifier": "super_test@example.org"}
        response = self.client.post(self.url, data)
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(self.identity.display_name(), response.content.decode("utf-8"))
        self.assertIn(self.superidentity.display_name(), response.content.decode("utf-8"))
        self.assertIn("name search is skipped", response.content.decode("utf-8"))

    @override_settings(KAMU_IDENTITY_SEARCH_LIMIT=1)
    def test_search_identity_partial_limit(self):
        self.create_identity(email=True)
        self.create_superidentity(email=True)
        data = {"surname": "user"}
        response = self.client.post(self.url, data)
        self.assertEqual(response.status_code, 200)
        self.assertIn(
            "Partial name matches returned too many results. Returning only exact matches.",
            response.content.decode("utf-8"),
        )
        self.assertNotIn(self.identity.display_name(), response.content.decode("utf-8"))
        self.assertIn(self.superidentity.display_name(), response.content.decode("utf-8"))

    @override_settings(KAMU_IDENTITY_SEARCH_LIMIT=1)
    def test_search_identity_total_limit(self):
        self.create_identity(email=True)
        self.identity.surname = "user"
        self.identity.save()
        self.create_superidentity(email=True)
        data = {"surname": "user"}
        response = self.client.post(self.url, data)
        self.assertEqual(response.status_code, 200)
        self.assertIn(
            "please refine your search parameters",
            response.content.decode("utf-8"),
        )

    def test_search_identity_without_permission(self):
        set_default_permissions(self.user, remove=True)
        data = {"given_names": "test", "email": "super@example.org"}
        response = self.client.post(self.url, data, follow=True)
        self.assertEqual(response.status_code, 403)

    def test_search_identity_phone(self):
        self.create_identity(phone=True)
        data = {"identifier": "+1234567890"}
        response = self.client.post(self.url, data)
        self.assertEqual(response.status_code, 200)
        self.assertIn(self.identity.display_name(), response.content.decode("utf-8"))

    @override_settings(ALLOW_TEST_FPIC=True)
    def test_search_identity_fpic(self):
        fpic = "010181-900C"
        self.create_identity()
        self.identity.fpic = fpic
        self.identity.save()
        data = {"identifier": fpic}
        response = self.client.post(self.url, data)
        self.assertEqual(response.status_code, 200)
        self.assertIn(self.identity.display_name(), response.content.decode("utf-8"))
        data = {"identifier": "010181-9234"}
        response = self.client.post(self.url, data)
        self.assertNotIn(self.identity.display_name(), response.content.decode("utf-8"))

    @override_settings(ALLOW_TEST_FPIC=True)
    @override_settings(SKIP_NAME_SEARCH_IF_IDENTIFIER_MATCHES=False)
    def test_search_identity_show_attributes(self):
        fpic = "010181-900C"
        uid = "testuseruid"
        self.create_identity(email=True, phone=True)
        self.identity.fpic = fpic
        self.identity.uid = uid
        self.identity.save()
        self.create_superidentity()
        superuid = "superuseruid"
        self.superidentity.uid = superuid
        self.superidentity.save()
        attributes = {
            "phone": self.phone_number.number,
            "email": self.email_address.address,
            "fpic": fpic,
            "uid": uid,
        }
        for attribute in attributes:
            data = {"identifier": attributes[attribute], "surname": "user"}
            response = self.client.post(self.url, data)
            self.assertEqual(response.status_code, 200)
            match attribute:
                case "email":
                    self.assertIn(f"<b>{self.email_address.address}</b>", response.content.decode("utf-8"))
                case "phone":
                    self.assertIn(f"<b>{self.phone_number.number}</b>", response.content.decode("utf-8"))
                case "fpic":
                    self.assertIn(f"<b>{fpic}</b>", response.content.decode("utf-8"))
                case "uid":
                    self.assertIn(f"<b>{uid}</b>", response.content.decode("utf-8"))
                    self.assertIn(superuid, response.content.decode("utf-8"))
                    self.assertNotIn(f"<b>{superuid}</b>", response.content.decode("utf-8"))

    def test_search_form_help_text(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertIn(
            "Returns partial matches in Kamu.",
            response.content.decode("utf-8"),
        )
        self.assertNotIn(
            "user directory",
            response.content.decode("utf-8"),
        )

    def test_search_form_reset(self):
        self.create_identity(phone=True)
        data = {"identifier": "+1234567890"}
        response = self.client.post(self.url, data)
        self.assertEqual(response.status_code, 200)
        self.assertIn("+1234567890", response.content.decode("utf-8"))
        response = self.client.post(self.url, {"reset_form": "Reset"})
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("+1234567890", response.content.decode("utf-8"))


class IdentityEditTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.create_identity(user=True)
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
            "given_names_verification": self.identity.given_names_verification,
            "surname_verification": self.identity.surname_verification,
            "date_of_birth_verification": self.identity.date_of_birth_verification,
            "gender_verification": self.identity.gender_verification,
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
        self.assertIn(
            'disabled aria-describedby="id_given_names_helptext" id="id_given_names"', response.content.decode("utf-8")
        )

    @override_settings(ATTRIBUTE_VERIFICATION_LEVEL_UNEDITABLE=0)
    def test_edit_own_information_disabled_fields_all(self):
        self.client.force_login(self.user)
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertIn(
            'disabled aria-describedby="id_given_names_helptext" id="id_given_names"', response.content.decode("utf-8")
        )
        self.assertIn(
            'disabled aria-describedby="id_gender_helptext" id="id_gender"', response.content.decode("utf-8")
        )

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
        self.assertIn(f"{self.identity.display_name()} |", response.content.decode("utf-8"))
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
        self.assertIn("Cannot set strong electrical verification manually", response.content.decode("utf-8"))

    def test_edit_lower_verification_level(self):
        self.create_superuser()
        self.identity.given_names_verification = Identity.VerificationMethod.STRONG
        self.identity.save()
        self.data["given_names"] = "New Name"
        self.data["given_names_verification"] = Identity.VerificationMethod.PHOTO_ID
        self.client.force_login(self.superuser)
        response = self.client.post(self.url, self.data)
        self.assertEqual(response.status_code, 302)

    def test_change_nationality(self):
        self.create_superuser()
        finland = self.create_country("FI")
        sweden = self.create_country("SE")
        nat = self.identity.nationalities.create(country=sweden)
        self.data["remove_nationality"] = nat.pk
        self.data["add_nationality"] = finland.pk
        self.data["add_nationality_verification"] = Identity.VerificationMethod.PHOTO_ID
        self.client.force_login(self.superuser)
        self.client.post(self.url, self.data)
        self.assertEqual(self.identity.nationalities.all().count(), 1)
        self.assertEqual(
            self.identity.nationalities.filter(
                country__code="FI", verification_method=Identity.VerificationMethod.PHOTO_ID
            ).count(),
            1,
        )

    def test_cannot_remove_verified_nationality(self):
        finland = self.create_country("FI")
        nat_fin = self.identity.nationalities.create(
            country=finland, verification_method=Identity.VerificationMethod.STRONG
        )
        self.data["remove_nationality"] = [nat_fin.pk]
        self.client.force_login(self.user)
        response = self.client.post(self.url, self.data)
        self.assertEqual(self.identity.nationalities.all().count(), 1)
        self.assertIn("Cannot remove verified nationality", response.content.decode("utf-8"))


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
        self.assertIn("Maximum number of email addresses reached", response.content.decode("utf-8"))

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

    def test_primary_email_change(self):
        new_number = EmailAddress.objects.create(
            identity=self.identity, address="new_address@examp.eorg", priority=1, verified=timezone.now()
        )
        data = {"email_up": new_number.pk}
        self.client.post(self.url, data, follow=True)
        self.assertIn("Primary email address changed", mail.outbox[0].subject)
        self.assertIn("If you did not make this change", mail.outbox[0].body)

    def test_primary_email_removed_by_superuser(self):
        superuser = self.create_superuser()
        self.client.force_login(superuser)
        EmailAddress.objects.create(
            identity=self.identity, address="new_address@examp.eorg", priority=1, verified=timezone.now()
        )
        data = {"email_remove": self.email_address.pk}
        self.client.post(self.url, data, follow=True)
        self.assertIn("Primary email address changed", mail.outbox[0].subject)
        self.assertIn("If you did not request this change", mail.outbox[0].body)


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
    def test_view_one_identifier(self, mock_logger):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertIn("identifier@example.org", response.content.decode("utf-8"))
        # Hide deactivate button if only one identifier
        self.assertNotIn("identifier_deactivate", response.content.decode("utf-8"))
        mock_logger.log.assert_has_calls(
            [
                call(20, "Listed identifier information", extra=ANY),
            ]
        )

    @override_settings(ALLOW_TEST_FPIC=True)
    @override_settings(LOCAL_EPPN_SUFFIX="@example.org")
    def test_view_multiple_identifiers(self):
        Identifier.objects.create(
            identity=self.identity,
            type=Identifier.Type.EPPN,
            value="identifier@example.com",
        )
        Identifier.objects.create(
            identity=self.identity,
            type=Identifier.Type.FPIC,
            value="010181-900C",
        )
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertIn(
            "You are deactivating user identifier from organisation with value identifier@example.com.",
            response.content.decode("utf-8"),
        )
        # Hide deactivations for local EPPN and FPIC identifiers
        self.assertNotIn("with value identifier@example.org", response.content.decode("utf-8"))
        self.assertNotIn("with value 010181-900C", response.content.decode("utf-8"))

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
        self.assertIn("Permission denied", response.content.decode("utf-8"))
        self.identifier.refresh_from_db()
        self.assertIsNone(self.identifier.deactivated_at)

    def test_deactivate_last_identifier_with_change_permissions(self):
        self.assertIsNone(self.identifier.deactivated_at)
        content_type = ContentType.objects.get(app_label="kamu", model="identity")
        permission = Permission.objects.get(content_type=content_type, codename="change_identifiers")
        self.user.user_permissions.add(permission)
        self.client.force_login(self.user)
        data = {"identifier_deactivate": self.identifier.pk}
        response = self.client.post(self.url, data, follow=True)
        self.assertIn("Deactivated identifier", response.content.decode("utf-8"))
        self.identifier.refresh_from_db()
        self.assertIsNotNone(self.identifier.deactivated_at)

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
        self.email_address.verified = None
        self.email_address.save()
        self.phone_number.verified = None
        self.phone_number.save()
        self.url = f"/email/{self.email_address.pk}/verify/"
        self.client = Client()
        self.client.force_login(self.user)

    def test_view_verification_page(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertIn("The verification code has now been sent", response.content.decode("utf-8"))

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
        self.assertIsNotNone(self.email_address.verified)
        mock_logger.log.assert_has_calls(
            [
                call(20, "Verified email address", extra=ANY),
            ]
        )

    @mock.patch("kamu.utils.audit.logger_audit")
    def test_verify_already_verified_address(self, mock_logger):
        self.create_superidentity()
        email = EmailAddress.objects.create(
            identity=self.superidentity, address=self.email_address.address, verified=timezone.now()
        )
        self._verify_address()
        self.email_address.refresh_from_db()
        self.assertIsNotNone(self.email_address.verified)
        email.refresh_from_db()
        self.assertIsNone(email.verified)
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
        self.assertIsNotNone(self.phone_number.verified)
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
            identity=self.superidentity, number=self.phone_number.number, verified=timezone.now()
        )
        self._verify_sms(mock_connector, self.phone_number)
        verified_number.refresh_from_db()
        self.assertIsNone(verified_number.verified)
        self.phone_number.refresh_from_db()
        self.assertIsNotNone(self.phone_number.verified)
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
        created_at = self.contract_template.created_at
        self.contract_template.name_en = "New name"
        self.contract_template.save()
        self.assertGreater(
            ContractTemplate.objects.get(type=self.contract_template.type, version=2).created_at, created_at
        )

    def test_contract_sign_page(self):
        response = self.client.get(f"/identity/{self.identity.pk}/contracts/{self.contract_template.pk}/sign/")
        self.assertIn(self.contract_template.name(), response.content.decode("utf-8"))
        self.assertIn(self.contract_template.text(), response.content.decode("utf-8"))
        self.assertIn(self.identity.display_name(), response.content.decode("utf-8"))

    @mock.patch("kamu.utils.audit.logger_audit")
    def test_contract_sign_contract(self, mock_logger):
        # User is redirected to identity details after signing contract
        response = self.client.post(
            f"/identity/{self.identity.pk}/contracts/{self.contract_template.pk}/sign/",
            {"sign_contract": self.contract_template.pk},
            follow=True,
        )
        self.assertTrue(Contract.objects.filter(identity=self.identity, template=self.contract_template).exists())
        self.assertIn("Contract signed", response.content.decode("utf-8"))
        self.assertIn("Identity information", response.content.decode("utf-8"))
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
        EmailAddress.objects.create(identity=self.identity, address="test1@example.org", verified=timezone.now())
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
            "Cannot combine two identities with Finnish personal identity code", response.content.decode("utf-8")
        )


class IdentityVerificationTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.create_identity(user=True)
        self.client = Client()
        self.client.force_login(self.user)
        self.url = f"/identity/{self.identity.pk}/verify/"

    def test_identity_verify_view(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Verify your identity Suomi.fi or eIDAS", response.content.decode("utf-8"))
        self.assertIn("Verify your identity using a biometric passport", response.content.decode("utf-8"))
        self.assertIn("Verify your identity at a lower level", response.content.decode("utf-8"))

    def test_identity_verify_view_already_verified(self):
        self.identity.assurance_level = Identity.AssuranceLevel.HIGH
        self.identity.save()
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Verify your identity Suomi.fi or eIDAS", response.content.decode("utf-8"))
        self.assertNotIn("Verify your identity using a biometric passport", response.content.decode("utf-8"))
        self.assertNotIn("Verify your identity at a lower level", response.content.decode("utf-8"))

    @override_settings(CANDOUR_API={})
    def test_identity_verify_view_without_candour(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Verify your identity Suomi.fi or eIDAS", response.content.decode("utf-8"))
        self.assertNotIn("Verify your identity using a biometric passport", response.content.decode("utf-8"))
        self.assertNotIn("Verify your identity at a lower level", response.content.decode("utf-8"))

    @override_settings(AUTHENTICATION_BACKENDS=["django.contrib.auth.backends.ModelBackend"])
    def test_identity_verify_view_without_suomifi(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("Verify your identity Suomi.fi or eIDAS", response.content.decode("utf-8"))
        self.assertIn("Verify your identity using a biometric passport", response.content.decode("utf-8"))
        self.assertIn("Verify your identity at a lower level", response.content.decode("utf-8"))

    @override_settings(SAML_SUOMIFI_SSN="HTTP_SSN")
    @override_settings(SAML_SUOMIFI_ASSURANCE="HTTP_ASSURANCE")
    @override_settings(ALLOW_TEST_FPIC=True)
    @mock.patch("kamu.utils.audit.logger_audit")
    def test_identity_verify_suomifi(self, audit_logger):
        response = self.client.post(
            self.url,
            data={"verify_identity": "suomifi"},
            follow=True,
            headers={"SSN": "010181-900C", "ASSURANCE": "http://ftn.ficora.fi/2017/loa3"},
        )
        self.assertEqual(response.status_code, 200)
        self.identity.refresh_from_db()
        self.assertEqual(self.identity.fpic, "010181-900C")
        self.assertEqual(self.identity.assurance_level, Identity.AssuranceLevel.HIGHEST)
        self.assertIn("Current verification level: Very high", response.content.decode("utf-8"))
        audit_logger.log.assert_has_calls(
            [
                call(
                    20,
                    "Linked fpic identifier to identity Tester Mc.",
                    extra=ANY,
                ),
            ]
        )

    def create_candour_response(self, status_code=200, json_data=None):
        response = Response()
        response.status_code = status_code
        if json_data is not None:
            response._content = json.dumps(json_data).encode("utf-8")
        return response

    @mock.patch("kamu.utils.audit.logger_audit")
    @mock.patch("requests.post", return_value=mock.MagicMock())
    def test_identity_verify_candour_start_view(self, mock_candour, audit_logger):
        mock_candour.return_value = self.create_candour_response(
            json_data={
                "verificationSessionId": "12345",
                "redirectUrl": "https://example.com/redirect",
            }
        )
        response = self.client.post(self.url, data={"verify_identity": "candour"})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, "https://example.com/redirect")
        self.identity.refresh_from_db()
        self.assertEqual(self.identity.candour_verification_session_id, "12345")
        audit_logger.log.assert_has_calls(
            [
                call(
                    20,
                    "Created Candour ID session: 12345",
                    extra=ANY,
                ),
            ]
        )

    @mock.patch("kamu.utils.audit.logger_audit")
    @mock.patch("requests.get", return_value=mock.MagicMock())
    def test_identity_verify_candour_verification_unfinished(self, mock_candour, audit_logger):
        mock_candour.return_value = self.create_candour_response(
            json_data={
                "status": "pending",
                "invitationLink": "https://example.com/redirect",
            }
        )
        self.identity.candour_verification_session_id = "12345"
        self.identity.save()
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertIn("You have unfinished Candour ID identification process", response.content.decode("utf-8"))
        self.assertNotIn("Verify with biometric passport", response.content.decode("utf-8"))

    @mock.patch("kamu.utils.audit.logger_audit")
    @mock.patch("requests.get", return_value=mock.MagicMock())
    def test_identity_verify_candour_verification_cancelled(self, mock_candour, audit_logger):
        mock_candour.return_value = self.create_candour_response(
            json_data={
                "status": "cancelled",
                "invitationLink": "https://example.com/redirect",
            }
        )
        self.identity.candour_verification_session_id = "12345"
        self.identity.save()
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Candour ID verification failed, please try again", response.content.decode("utf-8"))
        self.assertIn("Verify your identity using a biometric passport", response.content.decode("utf-8"))
        self.identity.refresh_from_db()
        self.assertIn(self.identity.candour_verification_session_id, "")

    @mock.patch("kamu.utils.audit.logger_audit")
    @mock.patch("requests.get", return_value=mock.MagicMock())
    def test_identity_verify_candour_verification_high(self, mock_candour, audit_logger):
        mock_candour.return_value = self.create_candour_response(
            json_data={
                "idDocumentType": "P<",
                "idNumber": "AB1234567",
                "idExpiration": "2030-12-31",
                "status": "finished",
                "identityVerified": True,
                "verificationMethod": "rfidApp",
                "firstName": "MICK ANDREW",
                "lastName": "O'REILLY",
                "dateOfBirth": "2001-01-01",
                "nationality": "SWE",
                "sex": "F",
            }
        )
        self.create_country(code="SE")
        self.identity.candour_verification_session_id = "12345"
        self.identity.save()
        response = self.client.get(self.url, follow=True)
        self.assertEqual(response.status_code, 200)
        self.identity.refresh_from_db()
        self.assertEqual(self.identity.assurance_level, Identity.AssuranceLevel.HIGH)
        self.assertEqual(self.identity.given_names, "Mick Andrew")
        self.assertEqual(self.identity.given_names_verification, Identity.VerificationMethod.STRONG)
        self.assertEqual(self.identity.surname, "O'Reilly")
        self.assertEqual(self.identity.surname_verification, Identity.VerificationMethod.STRONG)
        self.assertEqual(self.identity.date_of_birth, datetime.date(2001, 1, 1))
        self.assertEqual(self.identity.date_of_birth_verification, Identity.VerificationMethod.STRONG)
        self.assertEqual(self.identity.gender, "F")
        self.assertEqual(self.identity.gender_verification, Identity.VerificationMethod.STRONG)
        self.assertTrue(
            Identifier.objects.filter(
                identity=self.identity, type=Identifier.Type.ID, value="P:SWE:AB1234567"
            ).exists()
        )
        self.assertTrue(
            Nationality.objects.filter(
                identity=self.identity, country__code="SE", verification_method=Identity.VerificationMethod.STRONG
            )
        )
        audit_logger.log.assert_has_calls(
            [
                call(
                    20,
                    "Added identifier from Candour ID verification: P:SWE:AB1234567",
                    extra=ANY,
                ),
                call(
                    20,
                    "Added nationality SE to identity Tester Mc.",
                    extra=ANY,
                ),
                call(
                    20,
                    "Updated identity attributes: given_names, surname, date_of_birth, nationality, gender",
                    extra=ANY,
                ),
                call(
                    20,
                    "Updated identity assurance level from Candour ID verification to 3",
                    extra=ANY,
                ),
            ]
        )

    @mock.patch("kamu.utils.audit.logger_audit")
    @mock.patch("requests.get", return_value=mock.MagicMock())
    def test_identity_verify_candour_verification_invalid_document_info(self, mock_candour, audit_logger):
        mock_candour.return_value = self.create_candour_response(
            json_data={
                "idNumber": "AB1234567",
                "idExpiration": "2030-12-31",
                "status": "finished",
                "identityVerified": True,
                "verificationMethod": "rfidApp",
                "dateOfBirth": "2001-01-01",
                "nationality": "SWE",
            }
        )
        self.create_country(code="SE")
        self.identity.candour_verification_session_id = "12345"
        self.identity.save()
        response = self.client.get(self.url, follow=True)
        self.assertEqual(response.status_code, 200)
        self.identity.refresh_from_db()
        self.assertEqual(self.identity.assurance_level, Identity.AssuranceLevel.NONE)
        self.assertFalse(
            Identifier.objects.filter(
                identity=self.identity, type=Identifier.Type.ID, value="P:SWE:AB1234567"
            ).exists()
        )
        self.assertIsNone(self.identity.date_of_birth)
        audit_logger.log.assert_has_calls(
            [
                call(
                    30,
                    "Candour ID verification response missing identifier information",
                    extra=ANY,
                ),
            ]
        )
