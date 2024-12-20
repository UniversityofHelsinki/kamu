Logging
=======

Audit logging is done with :class:`kamu.utils.audit.AuditLog`. It is a helper class for Python logging module, that
provides a structured way to include additional information in log records.

Logging is done by calling either info, debug, or warning methods of the AuditLog instance.

Example
-------
.. code-block:: python

  audit_log.info(
      f"Membership to role {self.object.role} approved for identity: {self.object.identity}",
      category="membership",
      action="update",
      outcome="success",
      request=self.request,
      objects=[self.object, self.object.identity, self.object.role],
      log_to_db=True,
      f"Membership approved to role {self.object.role}",
  )

Method parameters
-----------------
.. automethod:: kamu.utils.audit.AuditLog.info
   :no-index:

Category values
---------------
.. autodata:: kamu.utils.audit.CategoryTypes

Action values
-------------
.. autodata:: kamu.utils.audit.ActionTypes

Outcome values
--------------
.. autodata:: kamu.utils.audit.OutcomeTypes

Information logged from objects
-------------------------------

User points to the target user. Actor is the user who initiated the action and it's picked from the request, if given.

If either User or Identity is given, information from the both are logged, if they are linked.

Account
~~~~~~~~
.. literalinclude:: ../../kamu/models/account.py
    :pyobject: Account.log_values

Contract
~~~~~~~~
.. literalinclude:: ../../kamu/models/contract.py
    :pyobject: Contract.log_values

ContractTemplate
~~~~~~~~~~~~~~~~
.. literalinclude:: ../../kamu/models/contract.py
    :pyobject: ContractTemplate.log_values

EmailAddress
~~~~~~~~~~~~
.. literalinclude:: ../../kamu/models/identity.py
    :pyobject: EmailAddress.log_values

Group
~~~~~
.. literalinclude:: ../../kamu/utils/audit.py
    :pyobject: AuditLog.log_values_group

Identifier
~~~~~~~~~~
.. literalinclude:: ../../kamu/models/identity.py
    :pyobject: Identifier.log_values

Identity
~~~~~~~~
.. literalinclude:: ../../kamu/models/identity.py
    :pyobject: Identity.log_values

Membership
~~~~~~~~~~
.. literalinclude:: ../../kamu/models/membership.py
    :pyobject: Membership.log_values

Nationality
~~~~~~~~~~~
.. literalinclude:: ../../kamu/models/identity.py
    :pyobject: Nationality.log_values

Permission
~~~~~~~~~~
.. literalinclude:: ../../kamu/models/role.py
    :pyobject: Permission.log_values

PhoneNumber
~~~~~~~~~~~
.. literalinclude:: ../../kamu/models/identity.py
    :pyobject: PhoneNumber.log_values

Requirement
~~~~~~~~~~~
.. literalinclude:: ../../kamu/models/role.py
    :pyobject: Requirement.log_values

Role
~~~~
.. literalinclude:: ../../kamu/models/role.py
    :pyobject: Role.log_values

Token
~~~~~
.. literalinclude:: ../../kamu/models/token.py
    :pyobject: Token.log_values

User
~~~~
.. literalinclude:: ../../kamu/utils/audit.py
    :pyobject: AuditLog.log_values_user