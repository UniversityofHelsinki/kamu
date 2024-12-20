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

Account update requests are stored to database and run by a background task.
