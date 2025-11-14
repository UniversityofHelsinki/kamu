"""
Updates organisation structure from the external service.
Currently, supports University of Helsinki organisation registry.

Usage help: ./manage.py update_organisation_structure -h
"""

from typing import Any

from django.conf import settings
from django.core.management.base import BaseCommand

from kamu.connectors.organisation import OrganisationApiConnector
from kamu.models.organisation import Organisation


class Command(BaseCommand):
    parent_post_update: dict[str, str] = {}
    verbosity: int = 0

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.organisation_api = getattr(settings, "ORGANISATION_API")

        if not self.organisation_api:
            self.stderr.write("ORGANISATION_API not configured")
            exit(1)
        self.identifier_key = self.organisation_api.get("IDENTIFIER_KEY", "uniqueId")
        self.name_en_key = self.organisation_api.get("NAME_EN_KEY", "nameEn")
        self.name_fi_key = self.organisation_api.get("NAME_FI_KEY", "nameFi")
        self.name_sv_key = self.organisation_api.get("NAME_SV_KEY", "nameSv")
        self.code_key = self.organisation_api.get("CODE_KEY", "code")
        self.abbreviation_key = self.organisation_api.get("ABBREVIATION_KEY", "abbreviation")

    def get_parent(self, organisation: dict) -> Organisation | None:
        """
        Get the parent organisation from the model or store it for later update if parent organisation has not yet
        been created.
        """
        parent_id = organisation.get("parent")
        if not parent_id:
            return None
        try:
            return Organisation.objects.get(identifier=parent_id)
        except Organisation.DoesNotExist:
            self.parent_post_update[organisation[self.identifier_key]] = parent_id
            return None

    def create_organisation(self, organisation: dict[str, str]) -> None:
        """
        Create a new organisation.
        """
        parent = self.get_parent(organisation)
        Organisation.objects.create(
            identifier=organisation[self.identifier_key],
            name_en=organisation.get(self.name_en_key, ""),
            name_fi=organisation.get(self.name_fi_key, ""),
            name_sv=organisation.get(self.name_sv_key, ""),
            code=organisation.get(self.code_key, ""),
            parent=parent,
        )
        if self.verbosity > 0:
            self.stdout.write(f"Organisation {organisation[self.identifier_key]} created")

    def update_organisation(self, organisation_obj: Organisation, organisation: dict[str, str]) -> None:
        """
        Update organisation information if it has changed.
        """
        save = False
        if organisation_obj.name_en != organisation.get(self.name_en_key, ""):
            organisation_obj.name_en = organisation.get(self.name_en_key, "")
            save = True
        if organisation_obj.name_fi != organisation.get(self.name_fi_key, ""):
            organisation_obj.name_fi = organisation.get(self.name_fi_key, "")
            save = True
        if organisation_obj.name_sv != organisation.get(self.name_sv_key, ""):
            organisation_obj.name_sv = organisation.get(self.name_sv_key, "")
            save = True
        if organisation_obj.code != organisation.get(self.code_key, ""):
            organisation_obj.code = organisation.get(self.code_key, "")
            save = True
        if (organisation_obj.parent and organisation_obj.parent.identifier != organisation.get("parent")) or (
            not organisation_obj.parent and organisation.get("parent")
        ):
            organisation_obj.parent = self.get_parent(organisation)
            save = True
        if save:
            organisation_obj.save()
            if self.verbosity > 0:
                self.stdout.write(f"Organisation {organisation_obj.identifier} updated")

    def post_update(self) -> None:
        """
        Update organisations with their parent organisation.
        """
        if self.parent_post_update:
            for organisation_id, parent_id in self.parent_post_update.items():
                try:
                    organisation_obj = Organisation.objects.get(identifier=organisation_id)
                    organisation_obj.parent = Organisation.objects.get(identifier=parent_id)
                    organisation_obj.save()
                    if self.verbosity > 0:
                        self.stdout.write(
                            f"Organisation {organisation_obj.identifier} updated with parent {parent_id}"
                        )
                except Organisation.DoesNotExist:
                    if self.verbosity > 0:
                        self.stdout.write(
                            f"Organisation {parent_id} not found, required by organisation {organisation_id}"
                        )

    def update_abbreviations(self, connector: OrganisationApiConnector) -> None:
        """
        Update organisation abbreviations from the different path.
        """
        organisations = connector.get_organisation_data(
            path=self.organisation_api.get("ABBREVIATION_PATH", "officialUnits")
        )
        for organisation in organisations:
            try:
                organisation_obj = Organisation.objects.get(identifier=organisation[self.identifier_key])
            except Organisation.DoesNotExist:
                continue
            abbreviation = organisation.get(self.abbreviation_key) or ""
            if organisation_obj.abbreviation != abbreviation:
                organisation_obj.abbreviation = abbreviation
                organisation_obj.save()
                if self.verbosity > 0:
                    self.stdout.write(
                        f"Organisation {organisation_obj.identifier} updated with abbreviation {abbreviation}"
                    )

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument("-n", "--dry-run", default=False, action="store_true", help="Dry run (no action)")

    def handle(self, **options: Any) -> None:
        self.verbosity = options["verbosity"]
        connector = OrganisationApiConnector()
        organisations = connector.get_organisation_data(
            path=self.organisation_api.get("STRUCTURE_PATH", "financeUnits")
        )
        for organisation in organisations:
            if not organisation.get(self.identifier_key):
                if self.verbosity > 0:
                    self.stdout.write(f"Organisation {organisation} has no identifier key {self.identifier_key}")
                continue
            try:
                organisation_obj = Organisation.objects.get(identifier=organisation[self.identifier_key])
            except Organisation.DoesNotExist:
                self.create_organisation(organisation)
                continue
            self.update_organisation(organisation_obj, organisation)
        self.post_update()
        self.update_abbreviations(connector)
