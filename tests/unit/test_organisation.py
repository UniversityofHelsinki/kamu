"""
Unit tests for roles.
"""

from django.contrib.auth import get_user_model

from tests.data import ORGANISATIONS
from tests.setup import BaseTestCase

User = get_user_model()


class BaseOrganisationTestCase(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.parent_organisation = self.create_organisation()
        self.organisation = self.create_organisation("research", parent=self.parent_organisation)


class OrganisationModelTests(BaseOrganisationTestCase):

    def test_organisation_name(self):
        self.assertEqual(self.organisation.name(), ORGANISATIONS["research"]["name_en"])
