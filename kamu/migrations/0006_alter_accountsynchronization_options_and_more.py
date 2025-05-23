# Generated by Django 4.2.17 on 2025-03-06 13:01

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("kamu", "0005_account_accountsynchronization"),
    ]

    operations = [
        migrations.AlterModelOptions(
            name="accountsynchronization",
            options={"verbose_name": "Account synchronisation", "verbose_name_plural": "Account synchronisations"},
        ),
        migrations.AlterModelOptions(
            name="emailaddress",
            options={
                "ordering": ["identity", "verified", "priority"],
                "verbose_name": "Email address",
                "verbose_name_plural": "Email addresses",
            },
        ),
        migrations.AlterField(
            model_name="identifier",
            name="type",
            field=models.CharField(
                choices=[
                    ("fpic", "Finnish personal identity code"),
                    ("eidas", "eIDAS identifier"),
                    ("eppn", "eduPersonPrincipalName"),
                    ("google", "Google account"),
                    ("microsoft", "Microsoft account"),
                    ("kamu", "Kamu identifier"),
                ],
                max_length=10,
                verbose_name="Identifier type",
            ),
        ),
        migrations.AlterField(
            model_name="identity",
            name="assurance_level",
            field=models.SmallIntegerField(
                choices=[
                    (0, "No assurance level"),
                    (1, "Low, self-asserted with a verified email-address"),
                    (2, "Medium, verified with a government issued photo-ID"),
                    (3, "High, eIDAS substantial level or similar"),
                ],
                default=0,
                help_text="How strongly this user identity is identified.",
                verbose_name="Assurance level",
            ),
        ),
        migrations.AlterField(
            model_name="identity",
            name="date_of_birth_verification",
            field=models.SmallIntegerField(
                choices=[
                    (0, "No verification"),
                    (1, "Self assurance"),
                    (2, "External source"),
                    (3, "Verified with a government issued photo-ID"),
                    (4, "Strong electrical verification"),
                ],
                default=0,
                verbose_name="Date of birth verification method",
            ),
        ),
        migrations.AlterField(
            model_name="identity",
            name="fpic_verification",
            field=models.SmallIntegerField(
                choices=[
                    (0, "No verification"),
                    (1, "Self assurance"),
                    (2, "External source"),
                    (3, "Verified with a government issued photo-ID"),
                    (4, "Strong electrical verification"),
                ],
                default=0,
                verbose_name="FPIC verification method",
            ),
        ),
        migrations.AlterField(
            model_name="identity",
            name="gender",
            field=models.CharField(
                choices=[("M", "Male"), ("F", "Female"), ("O", "Other"), ("U", "Unknown")],
                default="U",
                help_text="Required for the user identification from the official identity documents.",
                max_length=1,
                verbose_name="Gender",
            ),
        ),
        migrations.AlterField(
            model_name="identity",
            name="given_names",
            field=models.CharField(
                blank=True, help_text="All official given names.", max_length=200, verbose_name="Given names"
            ),
        ),
        migrations.AlterField(
            model_name="identity",
            name="given_names_verification",
            field=models.SmallIntegerField(
                choices=[
                    (0, "No verification"),
                    (1, "Self assurance"),
                    (2, "External source"),
                    (3, "Verified with a government issued photo-ID"),
                    (4, "Strong electrical verification"),
                ],
                default=0,
                verbose_name="Given names verification method",
            ),
        ),
        migrations.AlterField(
            model_name="identity",
            name="nationality",
            field=models.ManyToManyField(
                help_text="Required for the user identification from the official identity documents.",
                to="kamu.nationality",
                verbose_name="Nationality",
            ),
        ),
        migrations.AlterField(
            model_name="identity",
            name="nationality_verification",
            field=models.SmallIntegerField(
                choices=[
                    (0, "No verification"),
                    (1, "Self assurance"),
                    (2, "External source"),
                    (3, "Verified with a government issued photo-ID"),
                    (4, "Strong electrical verification"),
                ],
                default=0,
                verbose_name="Nationality verification method",
            ),
        ),
        migrations.AlterField(
            model_name="identity",
            name="surname_verification",
            field=models.SmallIntegerField(
                choices=[
                    (0, "No verification"),
                    (1, "Self assurance"),
                    (2, "External source"),
                    (3, "Verified with a government issued photo-ID"),
                    (4, "Strong electrical verification"),
                ],
                default=0,
                verbose_name="Surname verification method",
            ),
        ),
        migrations.AlterField(
            model_name="membership",
            name="expire_date",
            field=models.DateField(verbose_name="Membership expiry date"),
        ),
        migrations.AlterField(
            model_name="membership",
            name="status",
            field=models.CharField(
                choices=[
                    ("invited", "Invited"),
                    ("require", "Missing requirements"),
                    ("approval", "Waiting approval"),
                    ("pending", "Pending"),
                    ("active", "Active"),
                    ("expired", "Expired"),
                ],
                max_length=10,
                verbose_name="Membership status",
            ),
        ),
        migrations.AlterField(
            model_name="requirement",
            name="grace",
            field=models.IntegerField(
                default=0,
                help_text="Grace period (days) before membership status is changed.",
                verbose_name="Grace period (days)",
            ),
        ),
        migrations.AlterField(
            model_name="requirement",
            name="level",
            field=models.IntegerField(
                default=0,
                help_text="Require a minimum level of assurance or attribute verification level, or a minimum version "
                "of contract. Contract level must be a positive integer. Assurance levels are from 1 (low) to 3 "
                "(high) and attribute verification levels are from 1 (self assured) to 4 (strong electrical "
                "verification)",
                verbose_name="Level or version required",
            ),
        ),
        migrations.AlterField(
            model_name="requirement",
            name="type",
            field=models.CharField(
                choices=[
                    ("contract", "Requires a signed contract of type (value)"),
                    ("attribute", "User attribute (value) is defined"),
                    ("assurance", "Assurance level at least level"),
                    ("external", "External requirement"),
                ],
                max_length=20,
                verbose_name="Requirement type",
            ),
        ),
        migrations.AlterField(
            model_name="token",
            name="token_type",
            field=models.CharField(
                choices=[
                    ("emaillogin", "Email login token"),
                    ("phonelogin", "SMS login token"),
                    ("emailobjectverif", "Email object verification token"),
                    ("phoneobjectverif", "Phone object verification token"),
                    ("emailaddrverif", "Email address verification token"),
                    ("phonenumberverif", "Phone number verification token"),
                    ("invite", "Invite token"),
                ],
                max_length=17,
                verbose_name="Token type",
            ),
        ),
    ]
