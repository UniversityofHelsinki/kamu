"""
Test data generation.

Create basic fixtures and specified number of identities for development and testing.

Usage help: ./manage.py generate_test_data -h
"""

import datetime
import random
import unicodedata

import django.db.utils
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.management.base import BaseCommand
from faker import Faker

from identity.models import EmailAddress, Identity, PhoneNumber
from role.models import Membership, Permission, Role

fake = Faker()

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
        "set_inviters": False,
        "set_approvers": False,
        "set_owner": False,
    },
]


class Command(BaseCommand):
    def add_arguments(self, parser):
        parser.add_argument(
            "-i", type=int, default=0, action="store", dest="identities", help="Number of identities to generate"
        )
        parser.add_argument("-s", action="store_true", dest="silent", help="Don't print progress")

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
            Permission.objects.get_or_create(
                identifier=permission["identifier"],
                name_en=permission["name_en"],
                name_fi=permission["name_fi"],
                name_sv=permission["name_sv"],
                description_en=permission["description_en"],
                description_fi=permission["description_fi"],
                description_sv=permission["description_sv"],
                cost=permission["cost"],
            )

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
            for sub_role in role["sub_roles"]:
                sub_role_identifier = unicodedata.normalize("NFKD", sub_role).lower()
                s_role = Role.objects.get_or_create(
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
                )[0]
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

    def create_identities(self, number_of_identities) -> None:
        """
        Create identities.
        """
        if not self.silent:
            print("Loading attribute types...")
        if not self.silent:
            print("Creating identities...")
        start_time = datetime.datetime.now()
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
            given_names = []
            for r in range(random.randint(1, 4)):
                name = fake.first_name()
                if name not in given_names:
                    given_names.append(name)
            surname = fake.last_name()
            nickname = random.choice(given_names)
            identity = Identity.objects.create(
                given_names=" ".join(given_names),
                surname=surname,
                nickname=nickname,
                date_of_birth=fake.date_of_birth(minimum_age=17, maximum_age=80),
                preferred_language=random.choice(["fi", "en", "sv"]),
                nationality=fake.country_code(),
                gender=random.choice(["M", "N", "O", "U"]),
            )
            for r in range(random.randint(1, 2)):
                PhoneNumber.objects.create(
                    identity=identity,
                    number=f"{fake.country_calling_code()}{fake.msisdn()}"[:20],
                    priority=r,
                    verified=True,
                )
            for r in range(random.randint(1, 2)):
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
                    status = "expired" if expire_date < datetime.datetime.today() else "active"
                    Membership.objects.create(
                        identity=identity,
                        role=role,
                        reason="Because",
                        start_date=start_date,
                        expire_date=expire_date,
                        status=status,
                    )

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

    def handle(self, *args, **options):
        number_of_identities = options["identities"]
        self.silent = options["silent"]
        self.create_users()
        self.create_permissions()
        self.create_roles()
        self.create_identities(number_of_identities)
        self.set_user_identities()
