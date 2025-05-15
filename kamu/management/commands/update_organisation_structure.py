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

IDENTIFIER_KEY = getattr(settings, "ORGANISATION_API_IDENTIFIER_KEY", "uniqueId")
NAME_EN_KEY = getattr(settings, "ORGANISATION_API_NAME_EN_KEY", "nameEn")
NAME_FI_KEY = getattr(settings, "ORGANISATION_API_NAME_FI_KEY", "nameFi")
NAME_SV_KEY = getattr(settings, "ORGANISATION_API_NAME_SV_KEY", "nameSv")
CODE_KEY = getattr(settings, "ORGANISATION_API_CODE_KEY", "code")
ABBREVIATION_KEY = getattr(settings, "ORGANISATION_API_ABBREVIATION_KEY", "abbreviation")


class Command(BaseCommand):
    parent_post_update: dict[str, str] = {}
    verbosity: int = 0

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
            self.parent_post_update[organisation[IDENTIFIER_KEY]] = parent_id
            return None

    def create_organisation(self, organisation: dict[str, str]) -> None:
        """
        Create a new organisation.
        """
        parent = self.get_parent(organisation)
        Organisation.objects.create(
            identifier=organisation[IDENTIFIER_KEY],
            name_en=organisation.get(NAME_EN_KEY, ""),
            name_fi=organisation.get(NAME_FI_KEY, ""),
            name_sv=organisation.get(NAME_SV_KEY, ""),
            code=organisation.get(CODE_KEY, ""),
            parent=parent,
        )
        if self.verbosity > 0:
            self.stdout.write(f"Organisation {organisation[IDENTIFIER_KEY]} created")

    def update_organisation(self, organisation_obj: Organisation, organisation: dict[str, str]) -> None:
        """
        Update organisation information if it has changed.
        """
        save = False
        if organisation_obj.name_en != organisation.get(NAME_EN_KEY, ""):
            organisation_obj.name_en = organisation.get(NAME_EN_KEY, "")
            save = True
        if organisation_obj.name_fi != organisation.get(NAME_FI_KEY, ""):
            organisation_obj.name_fi = organisation.get(NAME_FI_KEY, "")
            save = True
        if organisation_obj.name_sv != organisation.get(NAME_SV_KEY, ""):
            organisation_obj.name_sv = organisation.get(NAME_SV_KEY, "")
            save = True
        if organisation_obj.code != organisation.get(CODE_KEY, ""):
            organisation_obj.code = organisation.get(CODE_KEY, "")
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
            path=getattr(settings, "ORGANISATION_API_ABBREVIATION_PATH", "officialUnits")
        )
        for organisation in organisations:
            try:
                organisation_obj = Organisation.objects.get(identifier=organisation[IDENTIFIER_KEY])
            except Organisation.DoesNotExist:
                continue
            if organisation_obj.abbreviation != organisation.get(ABBREVIATION_KEY, ""):
                abbreviation = organisation.get(ABBREVIATION_KEY, "")
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
            path=getattr(settings, "ORGANISATION_API_STRUCTURE_PATH", "financeUnits")
        )
        for organisation in organisations:
            if not organisation.get(IDENTIFIER_KEY):
                if self.verbosity > 0:
                    self.stdout.write(f"Organisation {organisation} has no identifier key {IDENTIFIER_KEY}")
                continue
            try:
                organisation_obj = Organisation.objects.get(identifier=organisation[IDENTIFIER_KEY])
            except Organisation.DoesNotExist:
                self.create_organisation(organisation)
                continue
            self.update_organisation(organisation_obj, organisation)
        self.post_update()
        self.update_abbreviations(connector)
