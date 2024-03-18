REST API
========

Kamu provides REST API for integrations.

API doesn't currently support object level permissions so it can't be used to provide backend for the public front end.

Authentication
--------------
Authentication is required and API uses token based authentication.

To authenticate, provide "Authorization" header with value "Token <your_token>".

Check https://www.django-rest-framework.org/api-guide/authentication/#tokenauthentication for more information.

Permissions
-----------
API uses Django's permission system to provide model wide CRUD permissions to API endpoints.

Validation
----------
API partially validates data, like unique constraints and field level content validation, but it doesn't support
most processes and can be used to bypass some of the business logic.