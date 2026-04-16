"""
Migrates accounts from LDAP to Kamu.

This is one time script that has limited test suite. Please use with caution and test in a safe
environment before running in production. Customise for your environment as needed.

Usage help: ./manage.py migrate_from_ldap -h
"""

import sys
import unicodedata
from datetime import date, datetime, time, timedelta
from typing import Any

from django.conf import settings
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.core.management import BaseCommand
from django.core.validators import validate_email
from django.db.models import Q
from django.utils import timezone

from kamu.connectors import ApiError
from kamu.connectors.ldap import LDAP_SIZELIMIT_EXCEEDED, ldap_search
from kamu.connectors.persondb import Person, PersonDBApiConnector
from kamu.models.account import Account
from kamu.models.identity import EmailAddress, Identifier, Identity
from kamu.models.membership import Membership
from kamu.models.role import Role
from kamu.utils.audit import AuditLog
from kamu.utils.identity import (
    get_identity_from_persondb,
    get_or_create_identity_from_persondb,
)
from kamu.validators.identity import validate_fpic

audit_log = AuditLog()


class MigrationSkipError(Exception):
    pass


class Command(BaseCommand):
    account_type: str = ""
    ldap_search_base: str = ""
    role: Role | None = None
    migration_user: User | None = None
    update_accounts: bool = False
    dry_run = False
    skip_email_match = False
    verify_email = False
    skip_account_synchronization = False
    attribute_mapping = {
        "uid": "uid",
        "givenName": "given_name_display",
        "sn": "surname_display",
        "schacDateOfBirth": "date_of_birth",
        "schacPersonalUniqueID": "fpic",
        "preferredLanguage": "preferred_language",
        "mail": "email_address",
        "schacExpiryDate": "account_expire_date",
    }
    ldap_attributes = list(attribute_mapping.keys())
    verbosity: int = 1

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument(
            "-a",
            "--accounts",
            type=str,
            default="",
            dest="accounts",
            help="Comma separated list of account UIDs to migrate.",
        )
        parser.add_argument(
            "-b",
            "--ldap-search-base",
            type=str,
            default="",
            dest="ldap_search_base",
            help="Base DN for LDAP search, e.g. 'ou=people,dc=example,dc=org'. Uses the value from settings by "
            "default.",
        )
        parser.add_argument(
            "-t",
            "--account-type",
            type=str,
            default="",
            dest="account_type",
            help="Creates accounts of given type, in addition to importing identity.",
        )
        parser.add_argument(
            "-r",
            "--role",
            type=str,
            default="",
            dest="role_identifier",
            help="Role identifier to which user is added.",
        )
        parser.add_argument(
            "-u",
            "--update",
            default=False,
            action="store_true",
            dest="update_accounts",
            help="If account already exists in Kamu, update identity information based on it.",
        )
        parser.add_argument(
            "-s",
            "--skip-email-match",
            default=False,
            action="store_true",
            dest="skip_email_match",
            help="Skip email match if names in existing identity and LDAP do not match.",
        )
        parser.add_argument(
            "-e",
            "--verify-email",
            default=False,
            action="store_true",
            dest="verify_email",
            help="Verify imported email addresses.",
        )
        parser.add_argument(
            "--skip-account-synchronisation",
            default=False,
            action="store_true",
            dest="skip_account_synchronization",
            help="Skip account synchronization for created accounts.",
        )
        parser.add_argument(
            "--dry-run",
            default=False,
            action="store_true",
            dest="dry_run",
            help="Do not import accounts, just print according to verbosity level.",
        )

    def get_person_from_ldap(self, uid: str) -> dict[str, str | date | None] | None:
        """
        Retrieves person data from LDAP and maps it to dictionary.

        Returns None if LDAP entry is not found or multiple entries are found for given UID.
        Raises MigrationSkipError if LDAP search fails.
        Parses attributes to matching Python types and logs warnings for invalid attribute data.
        """
        try:
            ldap_result = ldap_search(
                search_filter="(uid={})",
                search_values=[uid],
                ldap_attributes=self.ldap_attributes,
                search_base=self.ldap_search_base,
            )
        except LDAP_SIZELIMIT_EXCEEDED:
            self.message(f"LDAP search size limit exceeded for UID: {uid}", level=1, error=True)
            raise MigrationSkipError()
        if ldap_result is None:
            self.message(f"LDAP search failed. UID: {uid}", level=1, error=True)
            raise MigrationSkipError()
        if not ldap_result:
            self.message(f"LDAP entry for UID '{uid}' not found.", level=1, error=True)
            return None
        if len(ldap_result) > 1:
            self.message(f"Multiple LDAP entries for UID '{uid}' found.", level=1, error=True)
            return None
        result = ldap_result[0]
        ldap_person: dict[str, str | date | None] = {}
        for attribute in self.ldap_attributes:
            ldap_attribute = self.attribute_mapping[attribute]
            if attribute in ["schacDateOfBirth", "schacExpiryDate"]:
                date_string = result.get(attribute, None)
                if date_string:
                    try:
                        ldap_person[ldap_attribute] = datetime.strptime(date_string[:8], "%Y%m%d").date()
                    except ValueError:
                        ldap_person[ldap_attribute] = None
                        self.message(f"Invalid date '{date_string}' for UID '{uid}'.", level=1, error=True)
            elif attribute == "schacPersonalUniqueID":
                schac_value = result.get(attribute, None)
                if schac_value:
                    fpic = schac_value.split(":")[-1]
                    try:
                        validate_fpic(fpic)
                        ldap_person[ldap_attribute] = fpic
                    except ValidationError:
                        ldap_person[ldap_attribute] = None
                        self.message(f"Invalid FPIC '{fpic}' for UID '{uid}'.", level=1, error=True)
                else:
                    ldap_person[ldap_attribute] = None
            elif attribute == "mail":
                email_address = result.get(attribute, None)
                if email_address:
                    try:
                        validate_email(email_address)
                        ldap_person[ldap_attribute] = email_address
                    except ValidationError:
                        self.message(f"Invalid email address '{email_address}' for UID '{uid}'.", level=1, error=True)
                        ldap_person[ldap_attribute] = None
            else:
                ldap_person[ldap_attribute] = result.get(attribute, None)
        return ldap_person

    def check_name_match(
        self, ldap_person: dict[str, Any], identity: Identity | None = None, persondb_result: Person | None = None
    ) -> bool:
        """
        Checks if given name and surname from LDAP match with identity or PersonDB result.

        Compares names in a case-insensitive way and normalizes them to NFKD form.
        """
        ldap_given_name = unicodedata.normalize("NFKD", ldap_person.get("given_name_display", "").lower())
        ldap_surname = unicodedata.normalize("NFKD", ldap_person.get("surname_display", "").lower())
        if identity:
            given_name_display = unicodedata.normalize("NFKD", identity.given_name_display.lower())
            given_names = unicodedata.normalize("NFKD", identity.given_names.lower())
            surname_display = unicodedata.normalize("NFKD", identity.surname_display.lower())
            surname = unicodedata.normalize("NFKD", identity.surname.lower())
        elif persondb_result:
            given_name_display = unicodedata.normalize("NFKD", persondb_result.given_name_display.lower())
            given_names = unicodedata.normalize("NFKD", persondb_result.given_names.lower())
            surname_display = unicodedata.normalize("NFKD", persondb_result.surname_display.lower())
            surname = unicodedata.normalize("NFKD", persondb_result.surname.lower())
        else:
            return True
        if (
            ldap_given_name not in given_names
            and ldap_given_name not in given_name_display
            and given_name_display not in ldap_given_name
        ) or (
            ldap_surname not in surname and ldap_surname not in surname_display and surname_display not in ldap_surname
        ):
            self.message(
                f"WARNING: Existing identity found, but names differ for identity UID: {ldap_person['uid']}. "
                f"Identity names: {given_name_display} {surname_display}, LDAP names: "
                f"{ldap_given_name} {ldap_surname}.",
                level=2,
                error=False,
            )
            return False
        return True

    def find_person_from_persondb(self, ldap_person: dict[str, Any]) -> Person | None:
        """
        Searches for identity from PersonDB by given identifiers and email address.

        Returns Person if one found.

        Raises MigrationSkipError if
            1. multiple PersonDB results are found for given identifiers/email
            2. different identifiers/emails return conflicting PersonDB results
            3. if PersonDB API error occurs.
        """

        # Search PersonDB with identifiers and email address.
        try:
            connector = PersonDBApiConnector()
            if ldap_person.get("fpic"):
                fpic_result = connector.search_identifier(ldap_person["fpic"])
                if len(fpic_result):
                    self.message(
                        f"PersonDB search by FPIC '{ldap_person['fpic']}' returned {len(fpic_result)} results.",
                        level=3,
                        error=False,
                    )
            else:
                fpic_result = None
            if ldap_person.get("uid"):
                uid_result = connector.search_identifier(ldap_person["uid"])
                if len(uid_result):
                    self.message(
                        f"PersonDB search by UID '{ldap_person['uid']}' returned {len(uid_result)} results.",
                        level=3,
                        error=False,
                    )
            else:
                uid_result = None
            if ldap_person.get("email_address"):
                email_result = connector.search_email(ldap_person["email_address"])
                if len(email_result):
                    self.message(
                        f"PersonDB search by email '{ldap_person['email_address']}' returned "
                        f"{len(email_result)} results.",
                        level=3,
                        error=False,
                    )
            else:
                email_result = None
        except ApiError:
            self.message(
                "PersonDB API error occurred while searching for identity. UID: {ldap_person.get('uid')}",
                level=1,
                error=True,
            )
            raise MigrationSkipError()
        persondb_result = None

        # Check that there are no conflicting results and get PersonDB result if only one unique result is found.
        for result in [fpic_result, uid_result, email_result]:
            if result is None:
                continue
            if len(result) > 1:
                self.message(
                    f"Multiple PersonDB entries found for given identifier/email: "
                    f"{','.join([r.person_uuid for r in result])}."
                    f" UID: {ldap_person.get('uid')}",
                    level=1,
                    error=True,
                )
                raise MigrationSkipError()
            if len(result) == 1:
                person_temp = result.pop()
                if not persondb_result:
                    persondb_result = person_temp
                elif persondb_result != person_temp:
                    self.message(
                        f"Conflicting PersonDB entries found for given identifiers/emails: "
                        f"{persondb_result.person_uuid} and {person_temp.person_uuid}."
                        f" UID: {ldap_person.get('uid')}",
                        level=1,
                        error=True,
                    )
                    raise MigrationSkipError()

        if persondb_result:
            self.message(
                f"PersonDB result found for person UUID: {persondb_result.person_uuid}.",
                level=2,
                error=False,
            )
            if email_result and not fpic_result and not uid_result:
                if (
                    not self.check_name_match(ldap_person=ldap_person, identity=None, persondb_result=persondb_result)
                    and self.skip_email_match
                ):
                    self.message(
                        "Name mismatch for PersonDB result found by email, not using it for identity matching.",
                        level=2,
                        error=False,
                    )
                    return None
        return persondb_result

    def create_identity_from_persondb_result(self, person: Person, uid: str) -> Identity | None:
        """
        Creates Kamu Identity base on PersonDB person.
        """
        if self.dry_run:
            # In dry run, just check if identity matching PersonDB result already exists and log it. Returns None.
            try:
                identity = get_identity_from_persondb(person)
            except Identity.MultipleObjectsReturned:
                self.message(
                    f"[DRY RUN] Multiple identities found for PersonDB result: {person.person_uuid}. UID: {uid}",
                    level=2,
                    error=True,
                )
                raise MigrationSkipError()
            if identity:
                self.message(f"[DRY RUN] Identity matching PersonDB result found: {identity}", level=2, error=False)
            else:
                self.message(
                    f"[DRY RUN] Would create identity from PersonDB: {person.person_uuid}",
                    level=2,
                    error=False,
                )
            return None
        else:
            try:
                return get_or_create_identity_from_persondb(person)
            except Identity.MultipleObjectsReturned:
                self.message(
                    f"Multiple identities found for PersonDB result: {person.person_uuid}. UID: {uid}",
                    level=2,
                    error=True,
                )
                raise MigrationSkipError()

    def add_ldap_email_to_identity(self, identity: Identity, ldap_person: dict[str, Any]) -> None:
        """
        Adds email address to identity if it exists in LDAP and is not already associated with identity.
        """
        email_address = ldap_person.get("email_address")
        if email_address and not EmailAddress.objects.filter(identity=identity, address=email_address).exists():
            if self.dry_run:
                self.message(
                    f"[DRY RUN] Would create email address '{email_address}' for identity UID: {ldap_person['uid']}",
                    level=3,
                    error=False,
                )
            else:
                email_object = EmailAddress.objects.create(
                    identity=identity, address=email_address, verified=timezone.now() if self.verify_email else None
                )
                audit_log.info(
                    f"Created new email address from migration: {email_address}.",
                    category="email_address",
                    action="create",
                    outcome="success",
                    request=None,
                    objects=[identity, email_object],
                )
                self.message(
                    f"Added email address '{email_address}' to identity UID: {ldap_person['uid']}",
                    level=3,
                    error=False,
                )

    def add_ldap_fpic_to_identity(self, identity: Identity, ldap_person: dict[str, Any]) -> None:
        """
        Adds FPIC to identity if it exists in LDAP and identity has no FPIC.
        """
        fpic = ldap_person.get("fpic")
        if fpic and not Identifier.objects.filter(identity=identity, type=Identifier.Type.FPIC).exists():
            if self.dry_run:
                self.message(
                    f"[DRY RUN] Would create identifier '{fpic}' for identity UID: {ldap_person['uid']}",
                    level=3,
                    error=False,
                )
            else:
                identifier = Identifier.objects.create(identity=identity, type=Identifier.Type.FPIC, value=fpic)
                audit_log.info(
                    f"Created new identifier from migration: {identifier}.",
                    category="identifier",
                    action="create",
                    outcome="success",
                    request=None,
                    objects=[identity, identifier],
                )
                self.message(
                    f"Added identifier '{fpic}' to identity UID: {ldap_person['uid']}",
                    level=3,
                    error=False,
                )

    def get_or_create_identity(self, ldap_person: dict[str, Any], expire_date: date) -> Identity:
        """
        Retrieves existing identity if uid, fpic or email address matches to existing Kamu Identity.

        If existing Kamu Identity is not found and service uses PersonDB for Identity searches, check also
        PersonDB for existing identities.

        Otherwise, creates a new identity.

        If expire_date is in the past, sets created_at to expire_date for purge data calculations.

        May raise MigrationSkipError if multiple matches are found or PersonDB API error occurs.
        """
        created = False
        identity: Identity | None = None
        identity_email: Identity | None = None
        identity_fpic: Identity | None = None
        identity_uid: Identity | None = None

        # Check existing identity with uid
        try:
            identity_uid = (
                Identity.objects.filter(Q(uid=ldap_person["uid"]) | Q(useraccount__uid=ldap_person["uid"]))
                .distinct()
                .get()
            )
            self.message(f"Identity found by UID: {identity_uid}", level=2, error=False)
        except Identity.DoesNotExist:
            pass
        except Identity.MultipleObjectsReturned:
            self.message(f"Multiple identities found for UID '{ldap_person['uid']}'.", level=1, error=True)
            raise MigrationSkipError()

        # Check existing identity with fpic
        fpic = ldap_person.get("fpic")
        if fpic:
            try:
                identity_fpic = (
                    Identity.objects.filter(
                        Q(fpic=fpic) | Q(identifiers__type=Identifier.Type.FPIC, identifiers__value=fpic)
                    )
                    .distinct()
                    .get()
                )
                self.message(f"Identity found by FPIC: {identity_fpic}", level=2, error=False)
            except Identity.DoesNotExist:
                pass
            except Identity.MultipleObjectsReturned:
                self.message(
                    f"Multiple identities found for FPIC '{fpic}'. UID: {ldap_person['uid']}", level=1, error=True
                )
                raise MigrationSkipError()

        # Check existing identity with email_address
        email_address = ldap_person.get("email_address")
        if email_address:
            try:
                identity_email = Identity.objects.get(email_addresses__address=email_address)
                self.message(f"Identity found by email address: {identity_email}", level=2, error=False)
                if (
                    not self.check_name_match(ldap_person=ldap_person, identity=identity_email, persondb_result=None)
                    and self.skip_email_match
                ):
                    self.message("Name mismatch, not using email match.", level=2, error=False)
                    identity_email = None
            except Identity.DoesNotExist:
                pass
            except Identity.MultipleObjectsReturned:
                self.message(
                    f"Multiple identities found for email address '{email_address}'. UID: {ldap_person['uid']}",
                    level=1,
                    error=True,
                )
                raise MigrationSkipError()

        # Check that there are no conflicting results.
        for result in [identity_fpic, identity_uid, identity_email]:
            if result is None:
                continue
            if identity and identity != result:
                self.message(
                    f"Conflicting identities found for given identifiers/email: {identity} and {result}."
                    f" UID: {ldap_person.get('uid')}",
                    level=1,
                    error=True,
                )
                raise MigrationSkipError()
            identity = result

        if identity:
            self.message(f"Using existing identity for UID: {ldap_person['uid']}", level=2, error=False)

        # Check existing identity from PersonDB.
        if not identity and getattr(settings, "PERSONDB_SEARCH_FOR_INVITES", False):
            person = self.find_person_from_persondb(ldap_person)
            if person:
                identity = self.create_identity_from_persondb_result(person, ldap_person["uid"])

        # Create new identity if no existing identity is found.
        if not identity:
            if expire_date < date.today():
                created_at = timezone.make_aware(datetime.combine(expire_date, time()))
            else:
                created_at = timezone.now()
            # Using LDAP names for both display and official names as only one type exists for each account.
            # Verification method for name information is default, non-verified.
            given_name = ldap_person.get("given_name_display", "")
            surname = ldap_person.get("surname_display", "")
            identity = Identity(
                uid=ldap_person["uid"],
                assurance_level=Identity.AssuranceLevel.LOW,
                given_names=given_name,
                surname=surname,
                given_name_display=given_name,
                surname_display=surname,
                date_of_birth=ldap_person.get("date_of_birth", None),
                fpic=fpic,
                preferred_language=ldap_person.get("preferred_language", "en") or "en",
                allow_auth_with_unverified_contact=False if fpic else True,
                allow_auth_with_single_contact=False if fpic else True,
                created_at=created_at,
            )
            created = True
            if self.dry_run:
                self.message(f"[DRY RUN] Would create identity for UID: {ldap_person['uid']}", level=2, error=False)
            else:
                identity.save()
                audit_log.info(
                    f"Created new identity from migration: {identity}",
                    category="identity",
                    action="create",
                    outcome="success",
                    request=None,
                    objects=[identity],
                )
                self.message(f"Created identity for UID: {ldap_person['uid']}", level=2, error=False)
        self.add_ldap_email_to_identity(identity=identity, ldap_person=ldap_person)
        if created:
            self.add_ldap_fpic_to_identity(identity=identity, ldap_person=ldap_person)
        return identity

    def add_role_membership(self, identity: Identity, expire_date: date) -> Membership | None:
        """
        Adds role membership to identity if not already a member.

        Start date is set to today if expire date is in the future, otherwise to expire date.
        """
        if not self.role:
            return None
        if self.dry_run:
            self.message(
                f"[DRY RUN] Would add role '{self.role}' to identity UID: {identity.uid}", level=3, error=False
            )
            return None
        membership = Membership.objects.filter(identity=identity, role=self.role).first()
        if not membership:
            if expire_date > date.today():
                start_date = date.today()
            else:
                start_date = expire_date
            membership = Membership.objects.create(
                identity=identity,
                role=self.role,
                start_date=start_date,
                expire_date=expire_date,
                inviter=self.migration_user,
                approver=self.migration_user,
            )
            audit_log.info(
                f"Created new membership from migration: {membership}.",
                category="membership",
                action="create",
                outcome="success",
                request=None,
                objects=[identity, membership],
            )
            self.message(
                f"Added role '{self.role}' to identity UID: {identity.uid}, {start_date} - {expire_date}",
                level=3,
                error=False,
            )
        else:
            self.message(
                f"Membership to '{self.role}' already exists for identity UID: {identity.uid}, "
                f"{membership.start_date} - {membership.expire_date}",
                level=3,
                error=False,
            )
        return membership

    def create_account(self, identity: Identity, uid: str, expire_date: date) -> Account | None:
        """
        Creates account of given type for identity if not already existing.

        Calculates account status according to membership permissions.
        """
        try:
            account = Account.objects.get(uid=uid)
        except Account.DoesNotExist:
            if self.dry_run:
                self.message(
                    f"[DRY RUN] Would create account of type '{self.account_type}' for UID: {uid}",
                    level=2,
                    error=False,
                )
                return None
            if expire_date >= date.today():
                status = Account.Status.ENABLED
            else:
                status = Account.Status.EXPIRED
            account = Account.objects.create(identity=identity, type=self.account_type, uid=uid, status=status)
            account.update_status()
            audit_log.info(
                f"Created new account from migration: {account}.",
                category="account",
                action="create",
                outcome="success",
                request=None,
                objects=[identity, account],
            )
            self.message(f"Created account '{account.uid}' to identity: {identity}", level=2, error=False)
            if not self.skip_account_synchronization:
                account.accountsynchronization_set.update_or_create()
        return account

    def migrate_user(self, uid: str) -> bool:
        """
        Migrates a single user by UID.
        1. Checks if account already exists in Kamu.
        2. Retrieves person data from LDAP.
        3. Gets or creates identity.
        4. Adds role if specified.
        5. Creates account of given type if specified.
        """
        try:
            account = Account.objects.get(uid=uid)
            if account and not self.update_accounts:
                self.message(
                    f"Account with UID '{uid}' already exists, skipping identity and account creation.",
                    level=1,
                    error=False,
                )
                return False
        except Account.DoesNotExist:
            pass
        try:
            ldap_person = self.get_person_from_ldap(uid)
        except MigrationSkipError:
            return False
        if not ldap_person:
            return False
        expire_date = ldap_person.get("account_expire_date")
        if not expire_date or not isinstance(expire_date, date):
            self.message("No account expiry date found, skipping identity", level=1, error=True)
            return False
        if self.role:
            role_max_expire_date = timezone.localdate() + timedelta(days=self.role.maximum_duration)
            if expire_date > role_max_expire_date:
                self.message(
                    f"Account expiry date {expire_date} is later than role maximum expire date "
                    f"{role_max_expire_date}, limiting expiry date to role maximum.",
                    level=1,
                    error=False,
                )
                expire_date = role_max_expire_date
        try:
            identity = self.get_or_create_identity(ldap_person, expire_date)
        except MigrationSkipError:
            return False
        if self.role:
            self.add_role_membership(identity, expire_date)
        if self.account_type:
            self.create_account(identity, uid, expire_date)
        return True

    def message(self, message: str, level: int, error: bool = False) -> None:
        if self.verbosity >= level:
            if error:
                self.stderr.write(f"Error: {message}")
            else:
                self.stdout.write(message)

    def set_role_and_migration_user(self, role_identifier: str) -> tuple[Role | None, User | None]:
        """
        Sets role and migration user based on given role identifier.
        """
        if role_identifier:
            try:
                role = Role.objects.get(identifier=role_identifier)
            except Role.DoesNotExist:
                self.message(f"Role with identifier '{role_identifier}' does not exist.", level=1, error=True)
                sys.exit(2)
            self.message(f"Users will be added to role: {self.role}", level=1, error=False)

            migration_user_conf = getattr(settings, "MIGRATION_USER", {})
            username = migration_user_conf.get("username", "migration_script")
            try:
                migration_user = User.objects.get(username=username)
            except User.DoesNotExist:
                migration_user = User.objects.create(
                    username=username,
                    first_name=migration_user_conf.get("first_name", "migration"),
                    last_name=migration_user_conf.get("last_name", "script"),
                    is_active=False,
                )
                migration_user.set_unusable_password()
                migration_user.save()
                self.message(f"Created migration user: {migration_user}", level=1, error=False)
            return role, migration_user
        return None, None

    def handle(self, **options: Any) -> None:
        self.verbosity = options.get("verbosity", 1)
        accounts = options["accounts"]
        if not accounts:
            self.message("Accounts are required for migration.", level=1, error=True)
            sys.exit(2)

        self.account_type = options["account_type"].strip()
        if self.account_type and self.account_type not in Account.Type.values:
            self.message(
                f"Invalid account type '{self.account_type}', options are {', '.join(Account.Type.values)}.",
                level=1,
                error=True,
            )
            sys.exit(2)

        role_identifier = options["role_identifier"].strip()
        self.role, self.migration_user = self.set_role_and_migration_user(role_identifier)

        self.dry_run = options["dry_run"]
        self.update_accounts = options["update_accounts"]
        self.ldap_search_base = options["ldap_search_base"]
        self.skip_email_match = options["skip_email_match"]
        self.verify_email = options["verify_email"]
        self.skip_account_synchronization = options["skip_account_synchronization"]

        account_uids = [uid.strip() for uid in accounts.split(",") if uid.strip()]
        for uid in account_uids:
            if self.dry_run:
                self.message(f"[DRY RUN] Would migrate account with UID: {uid}", level=2, error=False)
            else:
                self.message(f"Migrating account with UID: {uid}", level=2, error=False)
            if self.migrate_user(uid) and not self.dry_run:
                self.message(f"Account with UID: {uid} migrated successfully.", level=2, error=False)
