Installation and configuration
==============================

Requirements
------------

- Python 3.8 or later
- MariaDB 10.4 or later
   - Any database supported by Django can be used, just install the appropriate database driver and update local_settings.py accordingly.

Some system libraries are required to install necessary Python dependencies:

- mariadb-devel
- openldap-devel

Development environment
-----------------------

Clone the repository and install the dependencies::

    git clone <url>  # Clone url
    cd kamu  # Change to the project directory
    python3 -m venv venv  # Create Python virtual environment
    source venv/bin/activate  # Activate the virtual environment
    pip install -r requirements_dev.txt  # Install the dependencies

Run tests using local SQLite database::

    python manage.py test

Run the development server::

    python manage.py migrate --settings=settings.test  # Run migrations, test settings use local SQLite.
    python manage.py runserver --settings=settings.test  # Run the development server

Generate test data::

    python manage.py generate_test_data -i X --settings=settings.test

Test data generation creates some users, organization, permissions, roles, contracts and X identities using them.

Log in with the Local login method using the created test users (username:password) with different roles:

- user:user (basic user without any permissions)
- admin:admin (administrator with superuser permissions)
- owner:owner (role owner with all the permissions for certain roles)
- approver:approver (approver permissions for some roles)
- inviter:inviter (inviter permissions for some roles)

Customize the settings
~~~~~~~~~~~~~~~~~~~~~~
To use a local database and connectors, or otherwise customize the settings, copy settings/local_settings_example.py to
settings/local_settings.py and modify the settings as needed.

Production environment
----------------------

Production environment is meant to be run with external web server to handle authentication, and an external database.

These examples are for Apache with mod_wsgi, Shibboleth SP and mod_auth_openidc.

Settings:

- Copy settings/local_settings_example.py to settings/local_settings.py and modify the settings as needed.
- Copy settings/logging.py to settings/local_logging.py to define file locations for audit and error logs.

Web site security
~~~~~~~~~~~~~~~~~
These examples are generic and don't cover securing the web site properly. Please consult the security guidelines of
the web server.

Kamu can work with quite strict settings. Boostrap 5 components are loaded from the cdn, so CSP must allow that::

    Header always set Content-Security-Policy "default-src 'self'; style-src 'self' https://cdn.jsdelivr.net; script-src 'self' https://cdn.jsdelivr.net"

To publish API schema, you have to set wider CSP for schema address::

    <Location /api/schema>
        Header always set Content-Security-Policy "default-src 'self'; img-src 'self' https://cdn.jsdelivr.net https://cdn.redoc.ly data:; style-src 'unsafe-inline' 'self' https://cdn.jsdelivr.net https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; script-src 'unsafe-inline' 'self' https://cdn.jsdelivr.net; worker-src 'self' blob:"
    </Location>

WSGI-configuration
~~~~~~~~~~~~~~~~~~
::

    WSGIDaemonProcess {{ wsgi_identifier }} user={{ kamu_user }} group={{ kamu_group }} python-home={{ kamu_virtual_env_dir }} python-path={{ kamu_git_dir }}
    WSGIProcessGroup {{ wsgi_identifier }}
    WSGIPassAuthorization On

    WSGIScriptAlias / {{ kamu_git_dir }}/wsgi.py process-group={{ wsgi_identifier }}

    Alias /static/ {{ kamu_static_dir }}

    <Directory {{ kamu_static_dir }}>
        Require all granted
    </Directory>

    <Directory {{ kamu_git_dir }}>
        <Files wsgi.py>
             Require all granted
        </Files>
    </Directory>

    <Location />
        Require all granted
    </Location>



Protecting authentication endpoints
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Protect each of the endpoints using Shibboleth SP in the Apache::

    <Location /login/haka>
        AuthType shibboleth
        ShibRequestSetting applicationId haka
        ShibRequestSetting requireSession 1
        require shib-session
    </Location>

    <Location /Shibboleth.sso/haka>
        SetHandler shib
        ShibRequestSetting applicationId haka
    </Location>



OIDC configuration
~~~~~~~~~~~~~~~~~~
To use multiple OIDC providers with mod_auth_openidc, you have to set up metadata directory according to documentation: https://github.com/OpenIDC/mod_auth_openidc/wiki/Multiple-Providers

Apache configuration for OIDC::

    OIDCMetadataDir {{ oidc_metadata_path }}
    OIDCRedirectURI https://{{ httpd_server_name}}/login/redirect_uri
    OIDCCryptoPassphrase {{ crypto_passphrase }}
    OIDCValidateIssuer Off  # If you want to use multi-tenant Microsoft authentication, you have to turn generic issuer validation off.

    <Location /login/google>
        AuthType openid-connect
        OIDCDiscoverURL https://{{ httpd_server_name}}/login/redirect_uri?iss=https%3A%2F%2Faccounts.google.com
        require claim iss:https://accounts.google.com
    </Location>

    <Location /login/microsoft>
        AuthType openid-connect
        OIDCDiscoverURL https://{{ httpd_server_name}}/login/redirect_uri?iss=https%3A%2F%2Flogin.microsoftonline.com%2F{{ microsoft_tenant_id }}%2Fv2.0
        require claim iss~https://login.microsoftonline.com/........-....-....-....-............/v2.0
    </Location>

    <Location /login/redirect_uri>
        AuthType openid-connect
        Require valid-user
    </Location>

