Memberships
===========

Membership is a relation between a identity and a role.

Membership defines the following information:
 - Identity.
 - Role.
 - Start and end date of the membership, possible time of the cancellation.
 - Reason for the membership.
 - Inviter and approver for the membership. These are Django user instances.
 - Possible invite email address, if the invite was sent by email and was not a direct addition from the Kamu or user
   directory.
 - Status of the membership.
 - Timestamp when the requirements have failed first time, if the membership was active. This is used to calculate
   the grace period for the requirements.

Status
------
Membership has a status, which can be one of the following:
 - Invited
    - Invite has been sent to the user by email but membership is not yet claimed.
 - Waiting requirements
    - Role has requirements that the user has not yet fulfilled.
 - Waiting approval
    - Membership is waiting for approval from the user with approval permissions.
 - Pending
    - All requirements are fulfilled and membership is waiting for start date.
 - Active
    - Membership is active.
 - Expired
    - Membership has expired.
 - Cancelled
    - Membership has been cancelled.

Membership status is checked each time the membership is saved. Status is usually also checked periodically by the
background process, using management scripts.

Adding and inviting users
-------------------------
Users can be added to a role by the following methods:
 - Direct addition from the Kamu or user directory.
 - Invite by email.

Any user with invite permissions to the role can add or invite users. When adding users from the user directory,
a new identity is created for the user and membership is linked to that identity.

When inviting users by email, unique invitation code is created and send to the user by email.

If the inviter has also approval permissions, the membership is automatically approved, otherwise the membership requires
approval from another user with approval permissions.

Multiple invites can be sent at once, if user has permissions given by the MASS_INVITE_PERMISSION_GROUPS setting. Setting
defined how many users can be invited at once. Users are checked from the Kamu with given identifying information:
email, phone number or Finnish personal identity code. Kamu users are added directly to the role, other users are
invited by email.

Claiming the invite
-------------------
User can claim the invitation by clicking the link in the invitation email or entering the invitation code on the registration
page.

If user already has a Kamu identity or user account in the user directory, they can just join in and the membership
is linked to that identity.

If user does not have a Kamu identity or user account in the user directory, they are asked to register with external
authentication method, or with email address and phone number, which are verified with a code sent to the address / number.

Managing memberships
--------------------
Role view:
 - Lists all role memberships.
 - Requires invite permissions to the role.

Expiring membership view:
 - Lists all membership that are expiring in the time period defined in the settings and user has at least invite
   permission to the role.

Approving membership view:
 - Lists all memberships that are waiting for approval.
 - Requires approval permissions to the role.

Membership view:
 - Shows the membership details and various tasks.
 - Approving membership:
    - Requires approval permissions.
 - Resending the invite email form the membership view:
    - Requires invite permissions to the role.
    - Can only be done if invite has not been claimed yet.
    - New invite code is created and old one is invalidated.
 - Ending membership:
    - Requires approval permissions.
    - User can also end their own membership.
 - Cancelling membership:
    - Requires approval permissions to the role.
 - Changing membership details, like end date or reason:
    - Requires approval permissions.
    - Updating membership clears cancellation.
