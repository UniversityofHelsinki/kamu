from django.contrib import admin
from rest_framework.authtoken.admin import TokenAdmin

from kamu.admin.identity import (
    ContractAdmin,
    ContractTemplateAdmin,
    EmailAddressAdmin,
    IdentifierAdmin,
    IdentityAdmin,
    PhoneNumberAdmin,
)
from kamu.admin.membership import MembershipAdmin
from kamu.admin.role import PermissionAdmin, RequirementAdmin, RoleAdmin
from kamu.models.contract import Contract, ContractTemplate
from kamu.models.identity import EmailAddress, Identifier, Identity, PhoneNumber
from kamu.models.membership import Membership
from kamu.models.role import Permission, Requirement, Role

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

TokenAdmin.raw_id_fields = ["user"]
TokenAdmin.list_display = ["user", "created"]
