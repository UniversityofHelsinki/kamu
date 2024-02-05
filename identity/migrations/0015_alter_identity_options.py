# Generated by Django 4.2.9 on 2024-02-01 11:00

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("identity", "0014_alter_identity_fpic_alter_identity_uid"),
    ]

    operations = [
        migrations.AlterModelOptions(
            name="identity",
            options={
                "permissions": [
                    ("view_basic_information", "Can view basic information"),
                    ("change_basic_information", "Can change basic information"),
                    ("view_restricted_information", "Can view restricted information"),
                    ("change_restricted_information", "Can change restricted information"),
                    ("view_contacts", "Can view contact information"),
                    ("change_contacts", "Can change contact information"),
                    ("view_contracts", "Can view contract information"),
                    ("view_identifiers", "Can view identifiers"),
                    ("change_identifiers", "Can change identifiers"),
                    ("search_identities", "Can search identities"),
                    ("combine_identities", "Can combine identities"),
                ],
                "verbose_name": "Identity",
                "verbose_name_plural": "Identities",
            },
        ),
    ]