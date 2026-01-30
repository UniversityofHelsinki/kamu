import logging
from dataclasses import dataclass
from datetime import date
from typing import Any

from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.validators import validate_email

from kamu.connectors import ApiConnector, ApiError
from kamu.models.identity import Country, Identifier, Identity
from kamu.validators.identity import validate_fpic, validate_phone_number

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class PersonAccount:
    """
    Imported account object.
    """

    username: str
    account_type: int
    account_subtype: int


@dataclass(frozen=True)
class PersonIdentifier:
    """
    Imported identifier object.
    """

    type: Identifier.Type
    value: str
    verification_level: Identity.VerificationMethod


@dataclass(frozen=True)
class PersonEmailAddress:
    """
    Imported email address object.
    """

    address: str
    verified: bool
    public: bool


@dataclass(frozen=True)
class PersonPhoneNumber:
    """
    Imported phone number object.
    """

    number: str
    verified: bool
    public: bool


@dataclass(frozen=True)
class Person:
    """
    Imported person object. Includes identity fields required by the Kamu.
    """

    person_uuid: str
    given_names: str
    given_names_verification: Identity.VerificationMethod
    surname: str
    surname_verification: Identity.VerificationMethod
    given_name_display: str
    surname_display: str
    date_of_birth: date | None
    date_of_birth_verification: Identity.VerificationMethod
    fpic: str | None
    fpic_verification: Identity.VerificationMethod
    preferred_language: str
    nationality: Country | None
    email_addresses: frozenset[PersonEmailAddress]
    phone_numbers: frozenset[PersonPhoneNumber]
    identifiers: frozenset[PersonIdentifier]
    accounts: frozenset[PersonAccount]


class PersonDBApiConnector(ApiConnector):
    """
    Connector for a person database.
    """

    api_name: str = "PersonDB"
    settings_dict_name: str = "PERSONDB_API"

    def get_person(self, person_uuid: str) -> Person | None:
        """
        Get person with identifier

        Raises ApiError on failure.
        """
        results = self.api_call(
            path=f"{self._self_get_path('GET_PERSON_PATH', 'person')}/{person_uuid}",
            http_method="get",
        )
        persons = self.parse_persons(results)
        if len(persons) == 0:
            return None
        if len(persons) == 1:
            return persons.pop()
        logger.error(f"Multiple persons found with UUID {person_uuid}.")
        raise ApiError(f"Multiple persons found with UUID {person_uuid}.")

    def search_identifier(self, identifier: str) -> set[Person]:
        """
        Search persons with identifier.

        Raises ApiError on failure.
        """
        results = self.api_call(
            path=self._self_get_path("SEARCH_IDENTIFIER_PATH", "search"),
            http_method="get",
            headers={"identifier": identifier},
        )
        persons = self.parse_persons(results)
        logger.debug(f"PersonDB search returned {len(persons)} results for identifier '{identifier}'.")
        return persons

    def search_generic(self, search_terms: dict[str, Any]) -> set[Person]:
        """
        Search persons with names and date of birth.

        "name" search parameter searches each part of the name from all name fields and returns matches where
        all parts are found in some name field.
        """
        search_data: dict[str, str] = {}
        given_names = search_terms.get("given_names", "")
        surname = search_terms.get("surname", "")
        if given_names or surname:
            search_data["name"] = f"{given_names} {surname}".strip()
        if date_of_birth := search_terms.get("date_of_birth", None):
            search_data["dateOfBirth"] = date_of_birth.isoformat()
        for term in search_terms:
            if term not in ["given_names", "surname", "date_of_birth"]:
                search_data[term] = search_terms[term]
        results = self.api_call(
            path=self._self_get_path("SEARCH_GENERIC_PATH", "searchperson"),
            http_method="post",
            data=search_data,
        )
        persons = self.parse_persons(results)
        logger.debug(f"PersonDB search returned {len(persons)} results for search terms '{search_data}'.")
        return persons

    def search_email(self, email_address: str) -> set[Person]:
        """
        Search persons with email address.

        Raises ApiError on failure.
        """
        persons = self.search_generic({"email": email_address})
        persons_email_ext = self.search_generic({"extEmail": email_address})
        return persons.union(persons_email_ext)

    def search_phone(self, phone_number: str) -> set[Person]:
        """
        Search persons with phone number.

        Raises ApiError on failure.
        """
        persons = self.search_generic({"mobilePhoneWork": phone_number})
        persons_mobile = self.search_generic({"mobilePhonePersonal": phone_number})
        return persons.union(persons_mobile)

    def parse_email_addresses(self, result: dict[str, Any]) -> frozenset[PersonEmailAddress]:
        """
        Parse email addresses from PersonDB result.

        {field}Tl-fields are trust_level in PersonDB and 30 means address is verified with sent code.
        """
        public_email_domains = getattr(settings, "PUBLIC_EMAIL_DOMAINS", [])
        email_addresses: set[PersonEmailAddress] = set()
        for address_field in ["email", "extEmail"]:
            address = result.get(address_field)
            if address:
                try:
                    validate_email(address)
                except ValidationError:
                    logger.error(f"Invalid email address format received from PersonDB: {address}.")
                    continue
                verified = True if result.get(address_field + "Tl", 0) >= 30 else False
                public = address.split("@")[1] in public_email_domains
                email_addresses.add(PersonEmailAddress(address=address, verified=verified, public=public))
        return frozenset(email_addresses)

    def parse_phone_numbers(self, result: dict[str, Any]) -> frozenset[PersonPhoneNumber]:
        """
        Parse phone numbers from PersonDB result.

        {field}Tl-fields are trust_level in PersonDB and 30 means number is verified with sent code.
        """
        phone_numbers: set[PersonPhoneNumber] = set()
        for number_field in ["mobilePhoneWork", "mobilePhonePersonal"]:
            data = result.get(number_field, "")
            if not data:
                continue
            number = data.strip().replace(" ", "")
            try:
                validate_phone_number(number)
            except ValidationError:
                logger.error(f"Invalid phone number format received from PersonDB: {number}.")
                continue
            if number:
                verified = True if result.get(number_field + "Tl", 0) >= 30 else False
                public = number_field == "mobilePhoneWork"
                phone_numbers.add(PersonPhoneNumber(number=number, verified=verified, public=public))
        return frozenset(phone_numbers)

    def parse_identifiers(self, result: dict[str, Any]) -> frozenset[PersonIdentifier]:
        """
        Parse identifiers from PersonDB result.
        """
        identifiers: set[PersonIdentifier] = set()
        try:
            identifiers.add(
                PersonIdentifier(
                    type=Identifier.Type.PERSON,
                    value=result["personUuid"],
                    verification_level=Identity.VerificationMethod.UNVERIFIED,
                )
            )
        except KeyError:
            logger.error("Invalid response received from PersonDB, result missing personUuid.")
            return frozenset(identifiers)
        person_identifiers = result.get("personIdentifiers", None)
        if not person_identifiers or not isinstance(person_identifiers, list):
            return frozenset(identifiers)
        for identifier in person_identifiers:
            id_type = identifier.get("identifierName")
            id_value = identifier.get("identifierValue")
            id_verification = self.map_verification_method(identifier.get("trustLevel", 0))
            id_types = ["ssn", "temporary_ssn"] if getattr(settings, "ALLOW_TEST_FPIC", False) else ["ssn"]
            if id_type in id_types:
                try:
                    validate_fpic(id_value)
                except (AttributeError, ValidationError):
                    logger.error(f"Invalid fpic format received from PersonDB: {id_value}.")
                    continue
                identifiers.add(
                    PersonIdentifier(type=Identifier.Type.FPIC, value=id_value, verification_level=id_verification)
                )
        return frozenset(identifiers)

    def parse_accounts(self, result: dict[str, Any]) -> frozenset[PersonAccount]:
        """
        Parse accounts from PersonDB result.
        """
        accounts: set[PersonAccount] = set()
        person_accounts = result.get("accounts", None)
        if not person_accounts or not isinstance(person_accounts, list):
            return frozenset(accounts)
        for account in person_accounts:
            try:
                accounts.add(
                    PersonAccount(
                        username=account["username"],
                        account_type=account["accountTypeId"],
                        account_subtype=account["accountSubtypeId"],
                    )
                )
            except KeyError:
                logger.error(f"Invalid account data received from PersonDB: {account}.")
                continue
        return frozenset(accounts)

    def parse_date(self, date_string: str | None) -> date | None:
        """
        Parse ISO format date string to date object.
        """
        if not date_string:
            return None
        try:
            return date.fromisoformat(date_string)
        except ValueError:
            logger.error(f"Invalid date format received from PersonDB: {date_string}.")
            return None

    def parse_nationality(self, nationality: str | None) -> Country | None:
        """
        Parse nationality string to Country.
        """
        if not nationality:
            return None
        try:
            return Country.objects.get(code=nationality.upper())
        except Country.DoesNotExist:
            logger.error(f"Invalid nationality code received from PersonDB: {nationality}.")
            return None

    def parse_language(self, language: str | None) -> str:
        """
        Parse preferred language string.
        """
        if not language:
            return "en"
        if language in [lang[0] for lang in Identity.LANG_CHOICES]:
            return language
        logger.error(f"Invalid preferred language received from PersonDB: {language}.")
        return "en"

    def map_verification_method(self, level: int) -> Identity.VerificationMethod:
        """
        Map PersonDB trust level to Identity verification method.
        """
        if level >= 50:
            return Identity.VerificationMethod.STRONG
        elif level >= 40:
            return Identity.VerificationMethod.PHOTO_ID
        elif level >= 20:
            return Identity.VerificationMethod.EXTERNAL
        elif level >= 10:
            return Identity.VerificationMethod.SELF_ASSURED
        else:
            return Identity.VerificationMethod.UNVERIFIED

    def parse_persons(self, results: list[dict[str, Any]]) -> set[Person]:
        """
        Map person database results to identity format.
        """
        parsed_results: set[Person] = set()
        for result in results:
            if not isinstance(result, dict) or "personUuid" not in result or not result["personUuid"]:
                logger.error(f"Invalid person data received from PersonDB: {result}.")
                continue
            identifiers = self.parse_identifiers(result)
            fpic = None
            fpic_verification = Identity.VerificationMethod.UNVERIFIED
            for identifier in identifiers:
                if identifier.type == Identifier.Type.FPIC:
                    fpic = identifier.value
                    fpic_verification = identifier.verification_level
            parsed_result = Person(
                person_uuid=result["personUuid"],
                given_names=result.get("officialGivenNames", ""),
                given_names_verification=self.map_verification_method(result.get("officialGivenNamesTl", 0)),
                surname=result.get("officialSurnames", ""),
                surname_verification=self.map_verification_method(result.get("officialSurnamesTl", 0)),
                given_name_display=result.get("preferredGivenName", ""),
                surname_display=result.get("preferredSurname", ""),
                date_of_birth=self.parse_date(result.get("dateOfBirth")),
                date_of_birth_verification=self.map_verification_method(result.get("dateOfBirthTl", 0)),
                fpic=fpic,
                fpic_verification=fpic_verification,
                preferred_language=self.parse_language(result.get("preferredLanguage")),
                nationality=self.parse_nationality(result.get("nationality")),
                email_addresses=self.parse_email_addresses(result),
                phone_numbers=self.parse_phone_numbers(result),
                identifiers=identifiers,
                accounts=self.parse_accounts(result),
            )

            parsed_results.add(parsed_result)
        return parsed_results
