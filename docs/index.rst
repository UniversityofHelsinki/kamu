Kamu
====
Kamu is the external user database for the University of Helsinki, built on top of Django and Bootstrap.

It's used to store and manage information about external users, i.e. people who are not students or staff at the
university.

Kamu is built for the needs of the University of Helsinki, but it's designed to be adaptable to other similar use
cases.

Main features
-------------
**Identity information management**

- Users can update their own information, such as name, email, phone etc.
- Staff with applicable permissions can update user information.
- Agreement/Contract management for users, i.e. signing NDA or similar agreements.

**Role and permission management**

- Hierarchical roles with defined permissions, owners and groups for invite and approval rights.
- All permissions are based on role membership.
- Roles and permissions can have required attributes or information, such as phone number or email defined,
  certain level of assurance, or a specific agreement signed.

**Membership management**

- Users with applicable permissions can invite or add new users to the role. People already in the system can be
  directly added to the role, others will receive an invitation by email.
- Membership will come in the effect, when all its requirements are satisfied:
    - User has registered to the system.
    - User has fulfilled requirements, such as filled in required attributes and signed all required agreements.
    - Membership has been approved by the role owner, or user with approval permissions to the role. Approval is
      automatic if the inviter also has approval permissions.
    - Membership period has started but not ended yet.

**User authentication**

- Staff will use their university accounts to authenticate to the system.
- External users can authenticate to the system with various methods, such as email and phone, Haka, eduGAIN and
  various external identity providers, or their university account if they have one based on their roles.
- Users can link multiple authentication methods to their account.

Documentation
=============
.. toctree::
   :maxdepth: 1

   content/technical
   content/installation
   content/contributing
   content/identities
   content/roles
   content/memberships
   content/accounts
   content/authentication
   content/logging
   content/api

Kamu class reference
====================
.. toctree::
   :maxdepth: 1

   modules/views
   modules/models
   modules/forms
   modules/utils
   modules/validators
   modules/api
   modules/serializers
   modules/connectors


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
