"""
Generate test data

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

from identity.models import Attribute, AttributeType, Identity
from role.models import Membership, Permission, Role

fake = Faker()


class Command(BaseCommand):
    def add_arguments(self, parser):
        parser.add_argument(
            "-i", type=int, default=0, action="store", dest="identities", help="Number of identities to generate"
        )

    def create_users(self) -> None:
        usermodel = get_user_model()
        users = ["user", "approver", "inviter", "owner"]
        try:
            usermodel.objects.create_superuser("admin", password="admin")
        except django.db.utils.IntegrityError:
            pass
        for user in users:
            try:
                u = usermodel.objects.create_user(user, password=user)
                g = Group.objects.get_or_create(name=user)[0]
                u.groups.add(g)
            except django.db.utils.IntegrityError:
                pass

    def create_permissions(self) -> None:
        """
        Create permissions
        """
        self.useraccount = Permission.objects.get_or_create(
            identifier="useraccount", name_en="User account", cost=130
        )[0]
        self.lightaccount = Permission.objects.get_or_create(
            identifier="lightaccount", name_en="Lightaccount", cost=0
        )[0]

    def create_roles(self) -> None:
        """
        Create roles with ugly hack.

        List elements:
        - String: Role name
        - List: Sub role names. Sub roles are created with name "Sub role name - Role name"
        - Boolean: 1 for useraccount, 0 for lightaccount
        - Boolean: 1 for adding approver, inviter and owner information, 0 for no linked groups or users

        """
        roles: list = [
            ("External employee", ["HY247", "HY+", "Unigrafia"], 1, 0),
            ("Consult", ["TIKE", "OPA", "HY247", "KK"], 1, 1),
            ("Research group external member", ["BYTDK", "HYMTDK", "MLTDK", "MMTDK"], 1, 0),
            ("Guest student", ["BYTDK", "HYMTDK", "MLTDK", "MMTDK"], 0, 0),
            ("External board member", [], 1, 0),
        ]
        for role in roles:
            name = role[0]
            identifier = unicodedata.normalize("NFKD", name)[0 : 20 if len(name) > 20 else len(name)]
            base_role = Role.objects.get_or_create(identifier=identifier, name_en=name, maximum_duration=365)[0]
            if role[2]:
                base_role.permissions.add(self.useraccount)
            else:
                base_role.permissions.add(self.lightaccount)
            for sub_role in role[1]:
                name = f"{sub_role} - {base_role.name_en}"
                identifier = unicodedata.normalize("NFKD", name)[0 : 20 if len(name) > 20 else len(name)]
                s_role = Role.objects.get_or_create(
                    identifier=identifier, name_en=name, parent=base_role, maximum_duration=365
                )[0]
                permission = Permission.objects.get_or_create(
                    identifier=unicodedata.normalize("NFKD", sub_role), name_en=sub_role, cost=0
                )[0]
                s_role.permissions.add(permission)
                if role[3]:
                    s_role.inviters.add(Group.objects.get(name="inviter"))
                    s_role.inviters.add(Group.objects.get(name="approver"))
                    s_role.approvers.add(Group.objects.get(name="approver"))
                    s_role.owner = get_user_model().objects.get(username="owner")
                    s_role.save()

    def create_identities(self, number_of_identities) -> None:
        attribute_first_names = AttributeType.objects.get_or_create(
            identifier="first_name", name_en="First name", multi_value=False, unique=False, regex_pattern=".*"
        )[0]
        attribute_last_names = AttributeType.objects.get_or_create(
            identifier="last_name", name_en="Last name", multi_value=False, unique=False, regex_pattern=".*"
        )[0]
        attribute_nickname = AttributeType.objects.get_or_create(
            identifier="nickname", name_en="Nickname", multi_value=False, unique=False, regex_pattern=".*"
        )[0]
        attribute_date_of_birth = AttributeType.objects.get_or_create(
            identifier="date_of_birth", name_en="Date of birth", multi_value=False, unique=False, regex_pattern=".*"
        )[0]
        attribute_email = AttributeType.objects.get_or_create(
            identifier="email", name_en="Email", multi_value=True, unique=False, regex_pattern=".*"
        )[0]
        for n in range(0, number_of_identities):
            first_names = []
            for r in range(0, random.randint(1, 4)):
                name = fake.first_name()
                if name not in first_names:
                    first_names.append(name)
            last_name = fake.last_name()
            nickname = random.choice(first_names)
            identity = Identity.objects.create(name=f"{nickname} {last_name}")
            Attribute.objects.create(
                identity=identity,
                attribute_type=attribute_first_names,
                value=" ".join(first_names),
                source="faker",
                validated=True,
            )
            Attribute.objects.create(
                identity=identity,
                attribute_type=attribute_last_names,
                value=last_name,
                source="faker",
                validated=True,
            )
            Attribute.objects.create(
                identity=identity,
                attribute_type=attribute_nickname,
                value=nickname,
                source="faker",
                validated=True,
            )
            Attribute.objects.create(
                identity=identity,
                attribute_type=attribute_date_of_birth,
                value=fake.date_of_birth(minimum_age=17, maximum_age=80).strftime("%Y-%m-%d"),
                source="faker",
                validated=True,
            )
            Attribute.objects.create(
                identity=identity,
                attribute_type=attribute_email,
                value=fake.email(),
                source="faker",
                validated=True,
            )

            def add_membership() -> None:
                role = Role.objects.exclude(parent=None).order_by("?").first()
                if role:
                    start_date = datetime.datetime.today() - datetime.timedelta(
                        days=random.randint(0, role.maximum_duration)
                    )
                    expire_date = start_date + datetime.timedelta(days=random.randint(0, role.maximum_duration))
                    Membership.objects.create(
                        identity=identity, role=role, reason="Because", start_date=start_date, expire_date=expire_date
                    )

            add_membership()
            if random.randint(0, 100) < 10:
                add_membership()

    def set_user_identities(self) -> None:
        users = get_user_model().objects.filter(identity__isnull=True)
        for user in users:
            identity = Identity.objects.filter(user__isnull=True).order_by("?").first()
            if identity:
                identity.user = user
                identity.save()

    def handle(self, *args, **options):
        number_of_identities = options["identities"]
        self.create_users()
        self.create_permissions()
        self.create_roles()
        self.create_identities(number_of_identities)
        self.set_user_identities()
