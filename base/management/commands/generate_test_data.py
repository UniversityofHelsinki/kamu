"""
Test data generation.

Create basic fixtures and specified number of identities for development and testing.

Usage help: ./manage.py generate_test_data -h
"""

import datetime
import random
import unicodedata
from typing import Any

import django.db.utils
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.management import call_command
from django.core.management.base import BaseCommand
from faker import Faker

from identity.models import (
    Contract,
    ContractTemplate,
    EmailAddress,
    Identity,
    Nationality,
    PhoneNumber,
)
from role.models import Membership, Permission, Requirement, Role

fake = Faker()

REQUIREMENTS: list = [
    {
        "name_en": "NDA signed",
        "name_fi": "Salassapitositoumus allekirjoitettu",
        "name_sv": "Sekretessavtal undertecknat",
        "type": Requirement.Type.CONTRACT,
        "value": "nda",
        "grace": 0,
    },
    {
        "name_en": "Secret contract signed",
        "name_fi": "Salainen sopimus allekirjoitettu",
        "name_sv": "Hemligt kontrakt undertecknat",
        "type": Requirement.Type.CONTRACT,
        "value": "secretcontract",
        "grace": 0,
    },
    {
        "name_en": "Phone number given",
        "name_fi": "Puhelinnumero annettu",
        "name_sv": "Telefonnummer angivet",
        "type": Requirement.Type.ATTRIBUTE,
        "value": "phone_number",
        "grace": 30,
    },
]

PERMISSIONS: list = [
    {
        "identifier": "useraccount",
        "name_en": "User account",
        "name_fi": "Käyttäjätunnus",
        "name_sv": "Användarnamn",
        "description_en": "Basic user account",
        "description_fi": "Normaali käyttäjätunnus",
        "description_sv": "Normalt användarnamn",
        "cost": 130,
    },
    {
        "identifier": "lightaccount",
        "name_en": "Lightaccount",
        "name_fi": "Kevyttunnus",
        "name_sv": "Lättkonto",
        "description_en": "User account with limited Access",
        "description_fi": "Käyttäjätunnus rajoitetulla pääsyllä",
        "description_sv": "Användarkonto med begränsad åtkomst",
        "cost": 130,
    },
]

ROLES: list = [
    {
        "identifier": "ext_employee",
        "name_en": "External employee",
        "name_fi": "Muun yrityksen työntekijä",
        "name_sv": "Extern anställd",
        "description_en": "External employee.",
        "description_fi": "Muun yrityksen työntekijä.",
        "description_sv": "Extern styrelseledamot.",
        "sub_roles": ["HY247", "HY+", "Unigrafia"],
        "permissions": ["useraccount"],
        "requirements": [],
        "purge_delay": 50,
        "set_inviters": False,
        "set_approvers": False,
        "set_owner": True,
    },
    {
        "identifier": "consultant",
        "name_en": "Consultant",
        "name_fi": "Konsultti",
        "name_sv": "Konsult",
        "description_en": "External consultant.",
        "description_fi": "Ulkopuolinen konsultti.",
        "description_sv": "Extern konsult.",
        "sub_roles": ["TIKE", "OPA", "HY247", "KK"],
        "permissions": ["useraccount"],
        "requirements": ["attribute:phone_number"],
        "purge_delay": 70,
        "set_inviters": True,
        "set_approvers": True,
        "set_owner": True,
    },
    {
        "identifier": "ext_research",
        "name_en": "Research group external member",
        "name_fi": "Tutkimusryhmän ulkoinen jäsen",
        "name_sv": "Forskningsgrupp extern medlem",
        "description_en": "Research group external member.",
        "description_fi": "Tutkimusryhmän ulkoinen jäsen.",
        "description_sv": "Forskningsgrupp extern medlem.",
        "sub_roles": ["BYTDK", "HYMTDK", "MLTDK", "MMTDK"],
        "permissions": ["useraccount"],
        "requirements": [],
        "purge_delay": 90,
        "set_inviters": False,
        "set_approvers": False,
        "set_owner": True,
    },
    {
        "identifier": "guest_student",
        "name_en": "Guest student",
        "name_fi": "Vieraileva opiskelija",
        "name_sv": "Gäststudent",
        "description_en": "Guest student.",
        "description_fi": "Vieraileva opiskelija.",
        "description_sv": "Gäststudent.",
        "sub_roles": ["BYTDK", "HYMTDK", "MLTDK", "MMTDK"],
        "permissions": ["lightaccount"],
        "requirements": [],
        "purge_delay": 110,
        "set_inviters": False,
        "set_approvers": False,
        "set_owner": True,
    },
    {
        "identifier": "ext_board",
        "name_en": "External board member",
        "name_fi": "Hallituksen ulkoinen jäsen",
        "name_sv": "Extern styrelseledamot",
        "description_en": "External board member",
        "description_fi": "Hallituksen ulkoinen jäsen",
        "description_sv": "Extern styrelseledamot",
        "sub_roles": [],
        "permissions": ["useraccount"],
        "requirements": ["contract:secretcontract"],
        "set_inviters": False,
        "set_approvers": False,
        "set_owner": False,
    },
]

CONTRACTS: list = [
    {
        "type": "nda",
        "name_en": "Non-disclosure agreement",
        "name_fi": "Salassapitosopimus",
        "name_sv": "Sekretessavtal",
        "text_en": "Non-disclosure agreement text.",
        "text_fi": "Salassapitosopimuksen teksti.",
        "text_sv": "Texten om sekretessavtal.",
        "public": True,
        "version": "1",
    },
    {
        "type": "textcontract",
        "name_en": "Test contract",
        "name_fi": "Testisopimus",
        "name_sv": "Testkontrakt",
        "text_en": "Test contract test.",
        "text_fi": "Salassapitosopimuksen teksti.",
        "text_sv": "Testkontrakttext.",
        "public": True,
        "version": "1",
    },
    {
        "type": "secretcontract",
        "name_en": "Secret contract",
        "name_fi": "Salainen sopimus",
        "name_sv": "Hemligt kontrakt",
        "text_en": "Secret contract test.",
        "text_fi": "Salaisen sopimuksen teksti.",
        "text_sv": "Hemlig kontraktstext.",
        "public": False,
        "version": "1",
    },
]


class Command(BaseCommand):
    def add_arguments(self, parser: Any) -> None:
        parser.add_argument(
            "-i", type=int, default=0, action="store", dest="identities", help="Number of identities to generate"
        )

    def load_fixtures(self) -> None:
        if Nationality.objects.count() == 0:
            call_command("loaddata", "nationality.json", app="identity", verbosity=(0 if self.silent else 1))

    def create_contracts(self) -> None:
        """
        Create contracts if they do not exist
        """
        if not self.silent:
            print("Creating contracts...")
        for contract in CONTRACTS:
            ContractTemplate.objects.get_or_create(
                type=contract["type"],
                name_en=contract["name_en"],
                name_fi=contract["name_fi"],
                name_sv=contract["name_sv"],
                text_en=contract["text_en"],
                text_fi=contract["text_fi"],
                text_sv=contract["text_sv"],
                version=contract["version"],
                public=contract["public"],
            )

    def create_requirements(self) -> None:
        """
        Create requirements if they do not exist
        """
        if not self.silent:
            print("Creating requirements...")
        for requirement in REQUIREMENTS:
            Requirement.objects.get_or_create(
                name_en=requirement["name_en"],
                name_fi=requirement["name_fi"],
                name_sv=requirement["name_sv"],
                type=requirement["type"],
                value=requirement["value"],
                grace=requirement["grace"],
            )

    def create_users(self) -> None:
        """
        Create users if they do not exist
        """
        if not self.silent:
            print("Creating users...")
        usermodel = get_user_model()
        users = ["user", "approver", "inviter", "owner"]
        try:
            usermodel.objects.create_superuser("admin", password="admin", first_name="Super", last_name="User")
        except django.db.utils.IntegrityError:
            pass
        for user in users:
            try:
                u = usermodel.objects.create_user(
                    user, password=user, first_name=user.capitalize(), last_name="Tester"
                )
                g = Group.objects.get_or_create(name=user)[0]
                u.groups.add(g)
            except django.db.utils.IntegrityError:
                pass

    def create_permissions(self) -> None:
        """
        Create permissions
        """
        if not self.silent:
            print("Creating permissions...")
        for permission in PERMISSIONS:
            perm, created = Permission.objects.get_or_create(
                identifier=permission["identifier"],
                name_en=permission["name_en"],
                name_fi=permission["name_fi"],
                name_sv=permission["name_sv"],
                description_en=permission["description_en"],
                description_fi=permission["description_fi"],
                description_sv=permission["description_sv"],
                cost=permission["cost"],
            )
            if created and perm.identifier == "useraccount":
                perm.requirements.add(Requirement.objects.get(type=Requirement.Type.CONTRACT, value="nda"))

    def create_roles(self) -> None:
        """
        Create roles with ugly hack.

        List elements:
        - String: Role name
        - List: Sub role names. Sub roles are created with name "Sub role name - Role name"
        - Boolean: 1 for useraccount, 0 for lightaccount
        - Boolean: 1 for adding approver, inviter and owner information, 0 for no linked groups or users

        """
        if not self.silent:
            print("Creating roles...")
        for role in ROLES:
            base_role = Role.objects.get_or_create(
                identifier=role["identifier"],
                name_en=role["name_en"],
                name_fi=role["name_fi"],
                name_sv=role["name_sv"],
                description_en=role["description_en"],
                description_fi=role["description_fi"],
                description_sv=role["description_sv"],
                organisation_unit="HY",
                maximum_duration=365,
            )[0]
            for permission in role["permissions"]:
                base_role.permissions.add(Permission.objects.get(identifier=permission))
            if "purge_delay" in role:
                base_role.purge_delay = role["purge_delay"]
                base_role.save()
            for sub_role in role["sub_roles"]:
                sub_role_identifier = unicodedata.normalize("NFKD", sub_role).lower()
                s_role, created = Role.objects.get_or_create(
                    identifier=f"{sub_role_identifier}_{base_role.identifier}"[:20],
                    name_en=f"{sub_role} - {base_role.name_en}",
                    name_fi=f"{sub_role} - {base_role.name_fi}",
                    name_sv=f"{sub_role} - {base_role.name_sv}",
                    description_en=f"{sub_role} - {base_role.description_en}",
                    description_fi=f"{sub_role} - {base_role.description_fi}",
                    description_sv=f"{sub_role} - {base_role.description_sv}",
                    parent=base_role,
                    organisation_unit=sub_role,
                    maximum_duration=365,
                )
                if created:
                    for requirement in role["requirements"]:
                        reqtype, reqvalue = requirement.split(":", 1)
                        req = Requirement.objects.filter(type=Requirement.Type(reqtype), value=reqvalue).first()
                        if req:
                            s_role.requirements.add(req)
                permission = Permission.objects.get_or_create(
                    identifier=unicodedata.normalize("NFKD", sub_role),
                    name_en=sub_role,
                    name_fi=sub_role,
                    name_sv=sub_role,
                    description_en=f"{sub_role} permissions",
                    description_fi=f"{sub_role} oikeudet",
                    description_sv=f"{sub_role} permissions",
                    cost=0,
                )[0]
                s_role.permissions.add(permission)
                if role["set_inviters"]:
                    s_role.inviters.add(Group.objects.get(name="inviter"))
                    s_role.inviters.add(Group.objects.get(name="approver"))
                if role["set_approvers"]:
                    s_role.approvers.add(Group.objects.get(name="approver"))
                if role["set_owner"]:
                    s_role.owner = get_user_model().objects.get(username="owner")
                s_role.save()

    def create_identities(self, number_of_identities: int) -> None:
        """
        Create identities.
        """
        if not self.silent:
            print("Creating identities...")
        user_approver = get_user_model().objects.get(username="approver")
        user_inviter = get_user_model().objects.get(username="inviter")
        user_owner = get_user_model().objects.get(username="owner")

        start_time = datetime.datetime.now()
        finnish_nationality = Nationality.objects.get(code="FI")
        contract_template = ContractTemplate.objects.filter(type="nda").order_by("-version").first()
        for n in range(number_of_identities):
            if not self.silent and n > 0 and n % 100 == 0:
                time_elapsed = datetime.datetime.now() - start_time
                time_expected = (number_of_identities / n) * time_elapsed
                seconds_remaining = (time_expected - time_elapsed).total_seconds()
                if seconds_remaining > 300:
                    time_remaining = f"{round(seconds_remaining / 60)} minutes"
                else:
                    time_remaining = f"{round(seconds_remaining)} seconds"
                print(f"Created {n}/{number_of_identities} identities, estimated remaining time: {time_remaining}")
            first_names = []
            for r in range(random.randint(1, 4)):
                name = fake.first_name()
                if name not in first_names:
                    first_names.append(name)
            if random.randint(0, 100) < 2:
                surname = ""
            else:
                surname = fake.last_name()
            if random.randint(0, 100) < 2 and not surname:
                given_names = ""
            else:
                given_names = " ".join(first_names)
            if random.randint(0, 100) < 10:
                given_name_display = ""
            else:
                given_name_display = random.choice(first_names)
            if random.randint(0, 100) < 10:
                date_of_birth = None
            else:
                date_of_birth = fake.date_of_birth(minimum_age=17, maximum_age=80)
            verification_level = random.choice(Identity.VerificationMethod.values)
            if verification_level == Identity.VerificationMethod.STRONG:
                assurance_level = Identity.AssuranceLevel.HIGH
            elif verification_level == Identity.VerificationMethod.PHOTO_ID:
                assurance_level = Identity.AssuranceLevel.MEDIUM
            elif (
                Identity.VerificationMethod.SELF_ASSURED <= verification_level <= Identity.VerificationMethod.EXTERNAL
            ):
                assurance_level = Identity.AssuranceLevel.LOW
            else:
                assurance_level = Identity.AssuranceLevel.NONE
            identity = Identity.objects.create(
                given_names=given_names,
                given_names_verification=verification_level,
                surname=surname,
                surname_verification=verification_level,
                given_name_display=given_name_display,
                date_of_birth=date_of_birth,
                date_of_birth_verification=verification_level,
                preferred_language=random.choice(["fi", "en", "sv"]),
                gender=random.choice(Identity.Gender.values),
                assurance_level=assurance_level,
            )
            rand = random.randint(0, 100)
            if 0 < rand < 50:
                identity.nationality.add(random.randint(1, 250))
            elif 50 <= rand < 90:
                identity.nationality.add(finnish_nationality)
            if 45 < rand < 55:  # Add second nationality
                identity.nationality.add(random.randint(1, 250))
            if identity.nationality.all().count() > 0:
                identity.nationality_verification = verification_level
                identity.save()
            if date_of_birth and (random.randint(0, 100) < 10 or finnish_nationality in identity.nationality.all()):
                year_part = date_of_birth.strftime("%d%m%y")
                if date_of_birth.year < 2000:
                    intermediate = "-"
                else:
                    intermediate = "A"
                numeric_part = str(random.randint(900, 999)).zfill(3)
                checksum_characters = "0123456789ABCDEFHJKLMNPRSTUVWXY"
                checksum = checksum_characters[int(year_part + numeric_part) % 31]
                identity.save()
                try:
                    identity.fpic = f"{year_part}{intermediate}{numeric_part}{checksum}"
                    identity.save()
                except django.db.utils.IntegrityError:
                    pass
            if contract_template and random.randint(0, 100) < 90:
                Contract.objects.sign_contract(contract_template, identity)
            for r in range(random.randint(0, 2)):
                PhoneNumber.objects.create(
                    identity=identity,
                    number=f"{fake.country_calling_code()}{fake.msisdn()}"[:20].replace(" ", ""),
                    priority=r,
                    verified=True,
                )
            for r in range(random.randint(0, 2)):
                EmailAddress.objects.create(
                    identity=identity,
                    address=fake.email(),
                    priority=r,
                    verified=True,
                )

            def add_membership() -> None:
                role = Role.objects.exclude(parent=None).order_by("?").first()
                if role:
                    start_date = datetime.datetime.today() - datetime.timedelta(
                        days=random.randint(0, role.maximum_duration)
                    )
                    expire_date = start_date + datetime.timedelta(days=random.randint(0, role.maximum_duration))
                    status = (
                        Membership.Status.EXPIRED
                        if expire_date < datetime.datetime.today()
                        else Membership.Status.ACTIVE
                    )
                    approver = None
                    if random.randint(0, 100) < 90:
                        inviter = user_inviter
                    else:
                        inviter = user_approver
                    if random.randint(0, 100) < 70:
                        approver = user_approver
                    elif random.randint(0, 100) < 50:
                        approver = user_owner
                    Membership.objects.create(
                        identity=identity,
                        role=role,
                        reason="Because",
                        inviter=inviter,
                        approver=approver,
                        start_date=start_date.date(),
                        expire_date=expire_date.date(),
                        status=status,
                    )

            if n == 0 or random.randint(0, 100) < 80:
                add_membership()
            if random.randint(0, 100) < 10:
                add_membership()

    def set_user_identities(self) -> None:
        """
        Set random identity to all users
        """
        users = get_user_model().objects.filter(identity__isnull=True)
        for user in users:
            identity = Identity.objects.filter(user__isnull=True).order_by("?").first()
            if identity:
                identity.user = user
                identity.save()

    def handle(self, **options: Any) -> None:
        number_of_identities = options["identities"]
        self.silent = options["verbosity"] == 0
        self.load_fixtures()
        self.create_users()
        self.create_requirements()
        self.create_permissions()
        self.create_roles()
        self.create_contracts()
        self.create_identities(number_of_identities)
        self.set_user_identities()
