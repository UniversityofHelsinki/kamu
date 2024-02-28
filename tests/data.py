"""
Data used in tests and test data generation.
"""

from kamu.models.role import Requirement

CONTRACT_TEMPLATES: dict = {
    "nda": {
        "type": "nda",
        "name_en": "Non-disclosure agreement",
        "name_fi": "Salassapitosopimus",
        "name_sv": "Sekretessavtal",
        "text_en": "Non-disclosure agreement text.",
        "text_fi": "Salassapitosopimuksen teksti.",
        "text_sv": "Texten om sekretessavtal.",
        "public": True,
        "version": "1",
    },
    "textcontract": {
        "type": "textcontract",
        "name_en": "Test contract",
        "name_fi": "Testisopimus",
        "name_sv": "Testkontrakt",
        "text_en": "Test contract test.",
        "text_fi": "Salassapitosopimuksen teksti.",
        "text_sv": "Testkontrakttext.",
        "public": True,
        "version": "1",
    },
    "secretcontract": {
        "type": "secretcontract",
        "name_en": "Secret contract",
        "name_fi": "Salainen sopimus",
        "name_sv": "Hemligt kontrakt",
        "text_en": "Secret contract test.",
        "text_fi": "Salaisen sopimuksen teksti.",
        "text_sv": "Hemlig kontraktstext.",
        "public": False,
        "version": "1",
    },
}

NATIONALITIES: dict = {
    "fi": {"code": "FI", "name_fi": "Suomi", "name_en": "Finland", "name_sv": "Finland"},
    "se": {
        "code": "SE",
        "name_fi": "Ruotsi",
        "name_en": "Sweden",
        "name_sv": "Sverige",
    },
}

PERMISSIONS: dict = {
    "useraccount": {
        "identifier": "useraccount",
        "name_en": "User account",
        "name_fi": "Käyttäjätunnus",
        "name_sv": "Användarnamn",
        "description_en": "Basic user account",
        "description_fi": "Normaali käyttäjätunnus",
        "description_sv": "Normalt användarnamn",
        "cost": 130,
    },
    "lightaccount": {
        "identifier": "lightaccount",
        "name_en": "Lightaccount",
        "name_fi": "Kevyttunnus",
        "name_sv": "Lättkonto",
        "description_en": "User account with limited Access",
        "description_fi": "Käyttäjätunnus rajoitetulla pääsyllä",
        "description_sv": "Användarkonto med begränsad åtkomst",
        "cost": 130,
    },
}

REQUIREMENTS: dict = {
    "contract_nda": {
        "name_en": "NDA signed",
        "name_fi": "Salassapitositoumus allekirjoitettu",
        "name_sv": "Sekretessavtal undertecknat",
        "type": Requirement.Type.CONTRACT,
        "value": "nda",
        "grace": 0,
    },
    "contract_secretcontract": {
        "name_en": "Secret contract signed",
        "name_fi": "Salainen sopimus allekirjoitettu",
        "name_sv": "Hemligt kontrakt undertecknat",
        "type": Requirement.Type.CONTRACT,
        "value": "secretcontract",
        "grace": 0,
    },
    "attribute_phone_nuber": {
        "name_en": "Phone number given",
        "name_fi": "Puhelinnumero annettu",
        "name_sv": "Telefonnummer angivet",
        "type": Requirement.Type.ATTRIBUTE,
        "value": "phone_number",
        "grace": 30,
    },
}

ROLES: dict = {
    "ext_employee": {
        "identifier": "ext_employee",
        "name_en": "External employee",
        "name_fi": "Muun yrityksen työntekijä",
        "name_sv": "Extern anställd",
        "description_en": "External employee.",
        "description_fi": "Muun yrityksen työntekijä.",
        "description_sv": "Extern styrelseledamot.",
        "maximum_duration": 365,
        "organisation_unit": "external",
        "notification_email_address": "hr@example.org",
        "notification_language": "en",
    },
    "consultant": {
        "identifier": "consultant",
        "name_en": "Consultant",
        "name_fi": "Konsultti",
        "name_sv": "Konsult",
        "description_en": "External consultant.",
        "description_fi": "Ulkopuolinen konsultti.",
        "description_sv": "Extern konsult.",
        "maximum_duration": 180,
        "organisation_unit": "consulting",
        "notification_email_address": "hr@example.org",
        "notification_language": "sv",
    },
    "ext_research": {
        "identifier": "ext_research",
        "name_en": "Research group external member",
        "name_fi": "Tutkimusryhmän ulkoinen jäsen",
        "name_sv": "Forskningsgrupp extern medlem",
        "description_en": "Research group external member.",
        "description_fi": "Tutkimusryhmän ulkoinen jäsen.",
        "description_sv": "Forskningsgrupp extern medlem.",
        "maximum_duration": 90,
        "organisation_unit": "research",
        "notification_email_address": "research@example.org",
        "notification_language": "en",
    },
    "guest_student": {
        "identifier": "guest_student",
        "name_en": "Guest student",
        "name_fi": "Vieraileva opiskelija",
        "name_sv": "Gäststudent",
        "description_en": "Guest student.",
        "description_fi": "Vieraileva opiskelija.",
        "description_sv": "Gäststudent.",
        "maximum_duration": 30,
        "organisation_unit": "studies",
        "notification_email_address": "teaching@example.org",
        "notification_language": "en",
    },
    "ext_board": {
        "identifier": "ext_board",
        "name_en": "External board member",
        "name_fi": "Hallituksen ulkoinen jäsen",
        "name_sv": "Extern styrelseledamot",
        "description_en": "External board member",
        "description_fi": "Hallituksen ulkoinen jäsen",
        "description_sv": "Extern styrelseledamot",
        "maximum_duration": 365,
        "organisation_unit": "board",
        "notification_email_address": "hr@example.org",
        "notification_language": "fi",
    },
}

USERS: dict = {
    "user": {"username": "user", "password": "user_pass", "first_name": "Tester", "last_name": "Mc. User"},
    "superuser": {
        "username": "superuser",
        "password": "superuser_pass",
        "first_name": "Dr. Super",
        "last_name": "User",
        "is_superuser": True,
        "is_staff": True,
    },
    "admin": {
        "username": "admin",
        "password": "admin_pass",
        "first_name": "Admin",
        "last_name": "Admin",
        "is_superuser": True,
        "is_staff": True,
    },
    "approver": {
        "username": "approver",
        "password": "approver_pass",
        "first_name": "Mr. App",
        "last_name": "Approver",
    },
    "inviter": {"username": "inviter", "password": "inviter_pass", "first_name": "In", "last_name": "Inviter"},
    "owner": {"username": "owner", "password": "owner_pass", "first_name": "Prof. O", "last_name": "Owner"},
}
