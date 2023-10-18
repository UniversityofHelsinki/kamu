# Generated by Django 4.2.5 on 2023-10-17 11:40

import django.db.models.deletion
import django.utils.timezone
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ("identity", "0002_initial"),
    ]

    operations = [
        migrations.CreateModel(
            name="AttributeType",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("name", models.CharField(max_length=255, unique=True, verbose_name="Attribute name")),
                ("multi_value", models.BooleanField(default=False, verbose_name="Multi value attribute")),
                ("unique", models.BooleanField(default=False, verbose_name="Require Unique value")),
                ("regex_pattern", models.CharField(max_length=255, verbose_name="Regex validation pattern")),
                ("created_at", models.DateTimeField(default=django.utils.timezone.now, verbose_name="Created at")),
                ("updated_at", models.DateTimeField(auto_now=True, verbose_name="Updated at")),
            ],
        ),
        migrations.AlterField(
            model_name="identity",
            name="user",
            field=models.OneToOneField(
                blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to=settings.AUTH_USER_MODEL
            ),
        ),
        migrations.CreateModel(
            name="Attribute",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("value", models.CharField(max_length=255, verbose_name="Attribute value")),
                ("source", models.CharField(max_length=20, verbose_name="Attribute source")),
                ("validated", models.BooleanField(default=False, verbose_name="Validated")),
                ("created_at", models.DateTimeField(default=django.utils.timezone.now, verbose_name="Created at")),
                ("updated_at", models.DateTimeField(auto_now=True, verbose_name="Updated at")),
                (
                    "attribute_type",
                    models.ForeignKey(on_delete=django.db.models.deletion.RESTRICT, to="identity.attributetype"),
                ),
                (
                    "identity",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE, related_name="attributes", to="identity.identity"
                    ),
                ),
            ],
        ),
    ]
