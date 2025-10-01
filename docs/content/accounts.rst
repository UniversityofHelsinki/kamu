Accounts
========

Account is a external user account managed by Kamu through API connector.

If user has a role membership that gives specific account permission, they can manage the account with Account views.

Allowed actions are:

- Create account
- Enable/disable account
- Reset account password

All account data except uid and password is generated from the Identity information. Password is given by the user and
uid is received from the external system when creating an account.

Account password validation can be defined with ACCOUNT_PASSWORD_VALIDATORS setting, using Django password validators.

Account information updates
---------------------------

Most updates are sent to the API immediately when the user submits the form.

Some updates are stored in the database and processed by a management task. The task checks account status and updates
it if needed. If an account’s status changes from enabled to disabled or expired, the account is locked.

When a user's details or membership change, all of the user's enabled accounts are added to the update queue.

When any account is viewed, its status is checked. If the status changes from enabled to disabled or expired, the
account is locked. If locking fails, the account is added to the update queue to retry later.
