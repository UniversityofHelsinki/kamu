Identities
==========

Identity is combination of user's information in the Kamu. Managing identities is one of the two main purposes
of the Kamu.

User information
----------------
There are various categories for user information. They are used to control who can view and edit the information.

Basic information
~~~~~~~~~~~~~~~~~
Basic information can be edited by the identity's owner, or users with the *change_basic_information* permission. It's shown
to users with the *view_basic_information* permission.

- Given names and Surname
    - Official first names and surname(s). Used for identifying user from the official documents.
    - Verification level is saved separately, based on the information source.
- Displayed given name and Displayed surname
    - A name user wishes to be called by. Used to create user accounts, email addresses etc.
    - Searchable to all users who manage groups in Kamu.
- Preferred language
- Assurance level
    - Level of assurance for the user's identity. How strongly user is identified.
- Kamu identifier
    - Unique identifier for the user in Kamu.
    - UUID4 format, used for linking the user to the other systems.
- UID
    - User identifier.
    - Used for linking the user to the other systems.

Restricted information
~~~~~~~~~~~~~~~~~~~~~~
Restricted information can be edited by the identity's owner, or users with the *change_restricted_information* permission.
It's shown to users with the *view_restricted_information* permission.

- Date of birth
    - Required for the user identification from the official identity documents.
    - Verification level is saved separately, based on the information source.
- Gender
    - Used for statistical purposes.
    - Allowed values are male, female, other (non-binary) and unknown (non-disclosed).
    - No verification information is saved.
- Nationality
    - Required for the user identification from the official identity documents.
    - Verification level is saved separately, based on the information source.
- Finnish personal identity code
    - Used for the strong electrical identification and linking to the other official databases.
    - Verification level is saved separately, based on the information source.

Contact information
~~~~~~~~~~~~~~~~~~~
Contact information can be edited by the identity's owner, or users with the *change_contacts* permission. It's shown to
users with the *view_contacts* permission.

Primary address is also shown to users with management permissions for groups the user is a member of. Identities
in Kamu can also be searched by email address or phone number, when adding users to the role.

- Email addresses
    - Used for the user identification and communication.
    - Verification is done with a code sent by email.
- Phone numbers
    - Used for the user identification and communication.
    - Verification is done with a code sent by SMS.

User's can add multiple email addresses and phone numbers.

Identifiers
~~~~~~~~~~~
Identifiers can be edited by the identity's owner, and viewed by users with the *view_identifiers* permission.

Users can link new identifiers to their identity for authentication purposes.

Users cannot remove identifiers by themselves, but they can deactivate them so that they cannot be used for
authentication. Old identifiers are saved for a specific time period, and then removed from the system.

When combining identities to remove duplicates, Kamu saves the source Kamu ID as a deactivated identifier to the target
identity.

Contracts
~~~~~~~~~
Contracts, or agreements, can be signed by the identity's owner, and viewed by users with the *view_contracts* permission.

Combining identities
--------------------
Duplicate identities always happen, no matter how you try to avoid them.

Users with combine_identities permission may combine two identities into one.

1. Identity can be set as a target or source for combining, in the identity view.
2. When both target and source is selected, user will be redirected to the confirmation page which lists all the
   information of both identities and the result of the combination.
3. For the basic and restricted information, target's information is used, unless it's empty, in which case source's
   information is used.
4. For the contact information, identifiers and contracts, all the information is combined.
