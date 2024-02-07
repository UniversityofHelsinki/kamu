# Generated by Django 4.2.9 on 2024-02-12 09:28

import django.utils.timezone
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("role", "0008_alter_role_options"),
    ]

    operations = [
        migrations.CreateModel(
            name="Requirement",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("name_fi", models.CharField(max_length=50, verbose_name="Requirement name (fi)")),
                ("name_en", models.CharField(max_length=50, verbose_name="Requirement name (en)")),
                ("name_sv", models.CharField(max_length=50, verbose_name="Requirement name (sv)")),
                (
                    "type",
                    models.CharField(
                        choices=[
                            ("contract", "Requires a signed contract of type (value)"),
                            ("attribute", "User attribute (value) is defined"),
                            ("assurance", "Assurance level at least the level"),
                            ("external", "External requirement"),
                        ],
                        max_length=20,
                        verbose_name="Requirement type",
                    ),
                ),
                ("value", models.CharField(blank=True, max_length=255, verbose_name="Requirement value")),
                (
                    "level",
                    models.IntegerField(
                        default=0,
                        help_text="Require a minimum level of assurance or attribute verification level, or a minimum version of contract. Contract level must be positive integer. Assurance levels are from 1 (low) to 3 (high) and attribute verification levels are from 1 (self assured) to 4 (strong electrical verification)",
                        verbose_name="Level or version required",
                    ),
                ),
                (
                    "grace",
                    models.IntegerField(
                        default=0,
                        help_text="Grace time (days) before membership status is changed.",
                        verbose_name="Grace time (days)",
                    ),
                ),
                ("created_at", models.DateTimeField(default=django.utils.timezone.now, verbose_name="Created at")),
                ("updated_at", models.DateTimeField(auto_now=True, verbose_name="Updated at")),
            ],
            options={
                "verbose_name": "Requirement",
                "verbose_name_plural": "Requirements",
                "ordering": ["type"],
            },
        ),
        migrations.AddField(
            model_name="membership",
            name="requirements_failed_at",
            field=models.DateTimeField(blank=True, null=True, verbose_name="Requirements failed time"),
        ),
        migrations.AddConstraint(
            model_name="requirement",
            constraint=models.UniqueConstraint(fields=("type", "value", "grace"), name="unique_requirement"),
        ),
        migrations.AddField(
            model_name="permission",
            name="requirements",
            field=models.ManyToManyField(
                blank=True, related_name="permission_requirements", to="role.requirement", verbose_name="Requirements"
            ),
        ),
        migrations.AddField(
            model_name="role",
            name="requirements",
            field=models.ManyToManyField(
                blank=True, related_name="role_requirements", to="role.requirement", verbose_name="Requirements"
            ),
        ),
    ]
