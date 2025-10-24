from django.contrib import admin
from django.contrib.auth.models import Group, User
from rest_framework.authtoken.models import TokenProxy

from kamu.admin.account import AccountAdmin
from kamu.admin.django import AuditGroupAdmin, AuditTokenAdmin, AuditUserAdmin
from kamu.admin.identity import (
    ContractAdmin,
    ContractTemplateAdmin,
    CountryAdmin,
    EmailAddressAdmin,
    IdentifierAdmin,
    IdentityAdmin,
    NationalityAdmin,
    PhoneNumberAdmin,
)
from kamu.admin.membership import MembershipAdmin
from kamu.admin.organisation import OrganisationAdmin
from kamu.admin.role import PermissionAdmin, RequirementAdmin, RoleAdmin
from kamu.models.account import Account
from kamu.models.contract import Contract, ContractTemplate
from kamu.models.identity import (
    Country,
    EmailAddress,
    Identifier,
    Identity,
    Nationality,
    PhoneNumber,
)
from kamu.models.membership import Membership
from kamu.models.organisation import Organisation
from kamu.models.role import Permission, Requirement, Role

admin.site.unregister(User)
admin.site.register(User, AuditUserAdmin)
admin.site.unregister(Group)
admin.site.register(Group, AuditGroupAdmin)
admin.site.unregister(TokenProxy)
admin.site.register(TokenProxy, AuditTokenAdmin)

admin.site.register(Account, AccountAdmin)
admin.site.register(Contract, ContractAdmin)
admin.site.register(ContractTemplate, ContractTemplateAdmin)
admin.site.register(Country, CountryAdmin)
admin.site.register(EmailAddress, EmailAddressAdmin)
admin.site.register(Identifier, IdentifierAdmin)
admin.site.register(Identity, IdentityAdmin)
admin.site.register(Nationality, NationalityAdmin)
admin.site.register(Membership, MembershipAdmin)
admin.site.register(Organisation, OrganisationAdmin)
admin.site.register(Permission, PermissionAdmin)
admin.site.register(PhoneNumber, PhoneNumberAdmin)
admin.site.register(Requirement, RequirementAdmin)
admin.site.register(Role, RoleAdmin)
