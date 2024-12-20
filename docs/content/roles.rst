Roles, permissions and requirements
===================================

Kamu includes a role and permission system. Roles and permissions are edited in the Django's admin site.

Roles
-----
Roles are used to define user's role in the organization. Kamu's role system is hierarchical, meaning that roles can
have a parent role. Role inherits permissions and requirements from its parent role.

Role defines the following information:

 - Text based identifier used for logging and internal use.
 - Name and description in multiple languages.
 - Optional parent role, which defines the hierarchy.
 - Organisation unit.
 - Owner, a Django user instance.
 - Inviters and approvers, which are groups of users who can invite and approve users to the role. They can point
   to multiple Django's groups.
 - Permissions the role provides to it's members, e.g. user account.
 - Requirements, that define what user needs to have to be a member of the role. E.g. signed s specific contract.
 - Maximum duration a membership can last, in days.
 - IAM group the role is linked to.
 - Purge delay, if defined, it overrides the global purge delay which is defined in the settings. Purge delay
   defines when the membership information is removed from the system after the membership has expired.

Owner, approvers and inviters:

 - Role owner has also approver and inviter permissions to the role.
 - Approvers have also inviter permissions to the role.

Permissions
-----------
Defines the permissions a member of the role has.

Permissions can have cost, value and requirements, in addition to type, identifier, name and description.
- Requirements work the same way as role requirements.
- Costs are used to define the cost of the membership, or a single user's total cost for all their roles.

Permission types are:

- account
   - User has permission to create account. Some accounts may be created through Kamu, others are linked to external
     systems.
- service
   - User has permission to use a service. These are used to limit light account access to specific services.
- generic
   - Generic permissions have no effect for the Kamu system itself, and are meant to be used by the external systems.

Requirements
------------
Requirements are used to define what a user needs to have to be a member of the role. Requirements have type, value,
level and grace.

Supported requirement types are:

- contract
   - Require a signed contract of contract template type specified in the requirement value.
   - If level is given, require at least that version of contract.
- attribute
   - identity is required to have attribute of the name "value". email_address and phone_number are supported values.
   - If level is given, require at least that verification level for the attribute.
- assurance
   - identity must have assurance_level of the level or higher.
- external
   - future type reservation, which always fails for now.

If the requirements tests for a membership fail but the membership is already active, a grace period is allowed before
membership revocation. Failure time is stored in the membership, so the period is calculated from the first time any
of the requirement fails.
