# Generated by Django 4.2.5 on 2024-01-10 13:24

from uuid import uuid4

from django.apps.registry import Apps
from django.db import migrations
from django.db.backends.base.schema import BaseDatabaseSchemaEditor


def gen_uuid(apps: Apps, schema_editor: BaseDatabaseSchemaEditor) -> None:
    identity = apps.get_model("identity", "Identity")
    for row in identity.objects.all():
        row.kamu_id = uuid4()
        row.save(update_fields=["kamu_id"])


class Migration(migrations.Migration):
    dependencies = [
        ("identity", "0008_identity_kamu_id_alter_identifier_type"),
    ]
    operations = [migrations.RunPython(gen_uuid)]