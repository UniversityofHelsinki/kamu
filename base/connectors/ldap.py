"""
LDAP connector
"""
import logging

import ldap
from django.conf import settings
from ldap.ldapobject import LDAPObject

logger = logging.getLogger(__name__)


def _ldap_initialize(
    remote: str,
    port: int,
    user: str,
    password: str,
    timeout: int = 5,
    cacertfile: str | None = None,
    use_ldaps: bool = True,
    ignore_tls_check: bool = False,
) -> LDAPObject:
    """
    Initializes LDAP connection
    """

    prefix = "ldap"
    if use_ldaps is True:
        prefix = "ldaps"
    if cacertfile:
        ldap.set_option(ldap.OPT_X_TLS_CACERTFILE, cacertfile)
    if ignore_tls_check:
        ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
    if timeout:
        ldap.set_option(ldap.OPT_NETWORK_TIMEOUT, timeout)
    ldap.set_option(ldap.OPT_REFERRALS, ldap.OPT_OFF)
    server = f"{ prefix }://{ remote }:{ port}"
    conn = ldap.initialize(server)
    conn.simple_bind_s(user, password)
    return conn


def _get_connection() -> LDAPObject | None:
    """
    Connects to LDAP using settings from Django settings
    """

    try:
        ldap_host = settings.LDAP_SETTINGS["HOST"]
        ldap_port = settings.LDAP_SETTINGS["PORT"]
        ldap_user = settings.LDAP_SETTINGS["USER"]
        ldap_password = settings.LDAP_SETTINGS["PASSWORD"]
        timeout = settings.LDAP_SETTINGS.get("TIMEOUT_SECONDS", 5)
        use_ldaps = settings.LDAP_SETTINGS.get("USE_LDAPS", True)
        cacertfile = settings.LDAP_SETTINGS.get("CACERTFILE", None)
        ignore_tls_check = settings.LDAP_SETTINGS.get("IGNORE_TLS_CHECK", False)
    except KeyError as e:
        log_msg = f"Incorrect LDAP settings, missing parameter LDAP_SETTINGS[{ e }]"
        logger.error(log_msg)
        return None
    try:
        ldap_connection = _ldap_initialize(
            ldap_host,
            ldap_port,
            ldap_user,
            ldap_password,
            timeout=timeout,
            cacertfile=cacertfile,
            use_ldaps=use_ldaps,
            ignore_tls_check=ignore_tls_check,
        )
    except ldap.SERVER_DOWN as e:
        log_msg = f"LDAP Server Down: { e }"
        logger.error(log_msg)
        return None
    except ldap.INVALID_CREDENTIALS:
        log_msg = "LDAP Invalid Credentials"
        logger.error(log_msg)
        return None
    except ldap.LDAPError as e:
        log_msg = f"LDAP ERROR: { e }"
        logger.error(log_msg)
        return None
    return ldap_connection


def _get_search_base() -> str | None:
    """
    Gets search base from settings
    """

    try:
        search_base = settings.LDAP_SETTINGS["SEARCH_BASE"]
    except KeyError as e:
        log_msg = f"Incorrect LDAP settings, missing parameter LDAP_SETTINGS[{ e }]"
        logger.error(log_msg)
        return None
    return search_base


def ldap_search(search_filter: str, ldap_attributes: list[str] | None = None) -> list | None:
    """
    Search LDAP

    Returns a list of dictionaries with LDAP attributes, or None if error.

    Raises ldap.SIZELIMIT_EXCEEDED if either server or local limit is exceeded.
    """
    if not ldap_attributes:
        ldap_attributes = getattr(settings, "LDAP_ATTRIBUTES")
    ldap_connection = _get_connection()
    search_base = _get_search_base()
    if not ldap_connection or not search_base or not search_filter or not ldap_attributes:
        return None
    try:
        result = ldap_connection.search_s(search_base, ldap.SCOPE_SUBTREE, search_filter, ldap_attributes)
    except ldap.NO_SUCH_OBJECT:
        log_msg = f"LDAP NO SUCH OBJECT: { search_base }"
        logger.error(log_msg)
        return None
    result_list: list = []
    if not result:
        return result_list
    if len(result) > getattr(settings, "LDAP_SEARCH_LIMIT", 50):
        raise ldap.SIZELIMIT_EXCEEDED
    for entry in result:
        obj = {}
        for key in ldap_attributes:
            obj["dn"] = entry[0]
            if key in entry[1]:
                obj[key] = entry[1][key][0].decode("utf-8")
        result_list.append(obj)
    return result_list
