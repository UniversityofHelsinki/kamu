from django.contrib import admin

from kamu.admin.identity import (
    ContractAdmin,
    ContractTemplateAdmin,
    EmailAddressAdmin,
    IdentifierAdmin,
    IdentityAdmin,
    PhoneNumberAdmin,
)
from kamu.admin.role import (
    MembershipAdmin,
    PermissionAdmin,
    RequirementAdmin,
    RoleAdmin,
)
from kamu.models.identity import (
    Contract,
    ContractTemplate,
    EmailAddress,
    Identifier,
    Identity,
    PhoneNumber,
)
from kamu.models.role import Membership, Permission, Requirement, Role

admin.site.register(Contract, ContractAdmin)
admin.site.register(ContractTemplate, ContractTemplateAdmin)
admin.site.register(EmailAddress, EmailAddressAdmin)
admin.site.register(Identifier, IdentifierAdmin)
admin.site.register(Identity, IdentityAdmin)
admin.site.register(PhoneNumber, PhoneNumberAdmin)
admin.site.register(Membership, MembershipAdmin)
admin.site.register(Permission, PermissionAdmin)
admin.site.register(Requirement, RequirementAdmin)
admin.site.register(Role, RoleAdmin)
