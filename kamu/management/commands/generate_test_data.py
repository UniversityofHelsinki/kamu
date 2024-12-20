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

from kamu.models.contract import Contract, ContractTemplate
from kamu.models.identity import EmailAddress, Identity, Nationality, PhoneNumber
from kamu.models.membership import Membership
from kamu.models.role import Permission, Requirement, Role
from tests.data import CONTRACT_TEMPLATES, PERMISSIONS, REQUIREMENTS, ROLES, USERS

fake = Faker()

ROLE_ADDONS: dict = {
    "ext_employee": {
        "sub_roles": ["HY247", "HY+", "Unigrafia"],
        "permissions": ["account"],
        "requirements": ["contract:nda"],
        "purge_delay": 50,
        "set_inviters": False,
        "set_approvers": False,
        "set_owner": True,
    },
    "consultant": {
        "sub_roles": ["TIKE", "OPA", "HY247", "KK"],
        "permissions": ["account"],
        "requirements": ["attribute:phone_number"],
        "purge_delay": 70,
        "set_inviters": True,
        "set_approvers": True,
        "set_owner": True,
    },
    "ext_research": {
        "sub_roles": ["BYTDK", "HYMTDK", "MLTDK", "MMTDK"],
        "permissions": ["lightaccount"],
        "requirements": [],
        "purge_delay": 90,
        "set_inviters": False,
        "set_approvers": False,
        "set_owner": True,
    },
    "guest_student": {
        "sub_roles": ["BYTDK", "HYMTDK", "MLTDK", "MMTDK"],
        "permissions": ["lightaccount"],
        "requirements": [],
        "purge_delay": 110,
        "set_inviters": False,
        "set_approvers": False,
        "set_owner": True,
    },
    "ext_board": {
        "sub_roles": [],
        "permissions": ["account"],
        "requirements": ["contract:secretcontract"],
        "set_inviters": False,
        "set_approvers": False,
        "set_owner": False,
    },
}


class Command(BaseCommand):
    def add_arguments(self, parser: Any) -> None:
        parser.add_argument(
            "-i", type=int, default=0, action="store", dest="identities", help="Number of identities to generate"
        )

    def load_fixtures(self) -> None:
        if Nationality.objects.count() == 0:
            call_command("loaddata", "nationality.json", app="kamu", verbosity=(0 if self.silent else 1))

    def create_contracts(self) -> None:
        """
        Create contracts if they do not exist
        """
        if not self.silent:
            print("Creating contracts...")
        for template in CONTRACT_TEMPLATES:
            ContractTemplate.objects.get_or_create(**CONTRACT_TEMPLATES[template])

    def create_requirements(self) -> None:
        """
        Create requirements if they do not exist
        """
        if not self.silent:
            print("Creating requirements...")
        for requirement in REQUIREMENTS:
            Requirement.objects.get_or_create(**REQUIREMENTS[requirement])

    def create_users(self) -> None:
        """
        Create users if they do not exist
        """
        if not self.silent:
            print("Creating users...")
        usermodel = get_user_model()
        for user in USERS:
            try:
                u = usermodel.objects.create_user(**USERS[user])
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
            perm, created = Permission.objects.get_or_create(**PERMISSIONS[permission])
            if created and perm.identifier == "account":
                perm.requirements.add(Requirement.objects.get(type=Requirement.Type.CONTRACT, value="nda"))

    def create_roles(self) -> None:
        """
        Create roles with ugly hack.

        List elements:
        - String: Role name
        - List: Sub role names. Sub roles are created with name "Sub role name - Role name"
        - Boolean: 1 for account, 0 for lightaccount
        - Boolean: 1 for adding approver, inviter and owner information, 0 for no linked groups or users

        """
        if not self.silent:
            print("Creating roles...")
        local_roles = []
        for role in ROLES:
            r = ROLES[role].copy()
            if ROLE_ADDONS.get(r["identifier"]):
                r.update(ROLE_ADDONS[r["identifier"]])
            local_roles.append(r)
        for role in local_roles:
            try:
                base_role = Role.objects.get(identifier=role["identifier"])
            except Role.DoesNotExist:
                base_role = Role.objects.create(
                    identifier=role["identifier"],
                    name_en=role["name_en"],
                    name_fi=role["name_fi"],
                    name_sv=role["name_sv"],
                    description_en=role["description_en"],
                    description_fi=role["description_fi"],
                    description_sv=role["description_sv"],
                    organisation_unit=role["organisation_unit"],
                    maximum_duration=role["maximum_duration"],
                )
            for permission in role["permissions"]:
                base_role.permissions.add(Permission.objects.get(identifier=permission))
            if "purge_delay" in role:
                base_role.purge_delay = role["purge_delay"]
                base_role.save()
            for sub_role in role["sub_roles"]:
                safe_sub_role_name = unicodedata.normalize("NFKD", sub_role).lower()
                sub_role_identifier = f"{safe_sub_role_name}_{base_role.identifier}"[:20]
                try:
                    s_role = Role.objects.get(identifier=sub_role_identifier)
                except Role.DoesNotExist:
                    s_role = Role.objects.create(
                        identifier=sub_role_identifier,
                        name_en=f"{sub_role} - {base_role.name_en}",
                        name_fi=f"{sub_role} - {base_role.name_fi}",
                        name_sv=f"{sub_role} - {base_role.name_sv}",
                        description_en=f"{sub_role} - {base_role.description_en}",
                        description_fi=f"{sub_role} - {base_role.description_fi}",
                        description_sv=f"{sub_role} - {base_role.description_sv}",
                        parent=base_role,
                        organisation_unit=sub_role,
                        maximum_duration=role["maximum_duration"],
                    )
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
            if (
                date_of_birth
                and isinstance(date_of_birth, datetime.date)
                and (random.randint(0, 100) < 10 or finnish_nationality in identity.nationality.all())
            ):
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
                    identity.fpic = None
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
