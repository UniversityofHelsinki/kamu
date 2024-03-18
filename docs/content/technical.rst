Technical information
=====================

Kamu is a Python Django application which uses Bootstrap 5 for the frontend.

Kamu is mostly built to use external authentication, where authentication protocols are handled by web
server modules.

It was designed for the Apache, Shibboleth SP, mod_shibd and mod_auth_openidc, but should work with any
other web server and authentication modules, which can require authentication for certain endpoints and provide
the user information iin environment variables. Read more from the :doc:`authentication`.

Required packages
-----------------
Packages required for production use:

- Django
   - Framework used for authentication, user management, database mapping, rendering templates etc.
   - https://www.djangoproject.com/
- djangorestframework
   - Framework used for creating RESTful APIs for integrations.
   - https://www.django-rest-framework.org/
- django-crispy-forms and crispy-bootstrap5
   - Used for rendering forms in a Bootstrap 5 compatible way.
   - https://django-crispy-forms.readthedocs.io/en/latest/
- django-filter
   - Filtering backend used in API.
   - https://github.com/carltongibson/django-filter/
- django-stubs-ext
   - Runtime monkey-patching for type hints.
   - https://github.com/typeddjango/django-stubs/
- drf-spectacular
   - OpenAPI 3 schema generation.
   - https://drf-spectacular.readthedocs.io/en/latest/
- mysqlclient
   - MySQL database connector. Could be replaced with another database connector.
   - https://pypi.org/project/mysqlclient/
- python-json-logger
   - JSON logging for Python, user for audit log.
   - https://pypi.org/project/python-json-logger/
- python-ldap
   - OpenLDAP library wrapper for Python. Used by LDAP connector.
   - https://www.python-ldap.org/en/latest/
- requests
   - HTTP library used by various connectors.
   - https://requests.readthedocs.io/en/latest/
