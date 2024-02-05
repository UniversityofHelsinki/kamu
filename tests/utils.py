"""
Various test classes and functions.
"""

from ldap import SIZELIMIT_EXCEEDED


class MockLdapConn:
    def __init__(self, limited_fields=False, size_exceeded=False):
        self.limited_fields = limited_fields
        self.size_exceeded = size_exceeded
        self.search_args = []

    LDAP_RETURN_VALUE_LIMITED_FIELDS = [
        (
            "uid=ldapuser,ou=users,dc=example,dc=org",
            {
                "uid": [b"ldapuser"],
                "cn": [b"Ldap User"],
                "mail": [b"ldap.user@example.org"],
            },
        )
    ]

    LDAP_RETURN_VALUE = [
        (
            "uid=ldapuser,ou=users,dc=example,dc=org",
            {
                "uid": [b"ldapuser"],
                "cn": [b"Ldap User"],
                "mail": [b"ldap.user@example.org"],
                "preferredLanguage": [b"en"],
                "givenName": [b"Ldap"],
                "sn": [b"User"],
                "schacDateOfBirth": [b"19810101"],
                "schacPersonalUniqueID": [b"urn:schac:personalUniqueID:fi:010181-900C"],
            },
        )
    ]

    def search_s(self, *args):
        self.search_args.append(args)
        if self.size_exceeded:
            raise SIZELIMIT_EXCEEDED
        if self.limited_fields:
            return self.LDAP_RETURN_VALUE_LIMITED_FIELDS
        return self.LDAP_RETURN_VALUE
