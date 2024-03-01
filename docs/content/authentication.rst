Authentication
==============

Settings
--------
Check local settings for activated backends and remote logout paths. EmailSMSBackend also requires SMS gateway
settings to be defined.

Backends
--------
There are generally three types of backends in this application.

- django.contrib.auth.backends.ModelBackend is the default Django password backend.
- kamu.backends.EmailSMSBackend is a custom backend for authenticating users with verification codes send by email
  and SMS.
- The rest are various remote login backends, using environment variables to get user information.

Every backend authenticates users against the Django user database.

Remote login backends
~~~~~~~~~~~~~~~~~~~~~

Remote backends do not handle any authentication protocol logic and are meant to be used with web server modules,
like mod_shibd and mod_auth_openidc in Apache.

Environment variables used to get user information for each backend are specified in the common settings. They can
be overwritten in the local settings.

Unique identifiers provided by the backends are linked to the user's identity.

The backends can be customized by subclassing them and overriding various methods, like:

-  post_authentication_tasks
    - Custom tasks to run after successful authentication. Like updating user information.
    - Groups are updated if group prefixes for the backend are defined in the config (BACKEND_GROUP_PREFIXES).
      Optionally groups with prefixes defined in other backends can be removed from the user
      (REMOVE_GROUPS_WITH_OTHER_BACKENDS).
- _get_identifier_type
    - Defines the Identifier type used to save backend's unique identifier. Values are from the Identifier model
      choices.
- _get_meta_unique_identifier
    - Parses unique identifier from request.META.
- _get_meta_user_info
    - Parses user information from request.META.
- _get_username_suffix
    - Custom username suffix to use when creating new user account.
- _validate_issuer
    - Custom issuer validation method. Authentication fails if this returns False.

Remote login backends have their own login endpoints, which must be protected by the external applications:

- login/shibboleth/ (SAML2)
   - Local SAML authentication.
   - Backend: kamu.backends.ShibbolethLocalBackend
- login/haka/
   - Haka authentication (SAML2)
   - Backend: kamu.backends.ShibbolethHakaBackend
- login/edugain/
   - eduGAIN authentication (SAML2)
   - Backend: kamu.backends.ShibbolethEdugainBackend
- login/google/
   - Google Authentication (OIDC)
   - Backend: kamu.backends.GoogleBackend
- login/microsoft/
   - Microsoft Authentication (OIDC)
   - Backend: kamu.backends.MicrosoftBackend
- login/suomifi/
   - Suomi.fi / eIDAS authentication (SAML2)
   - Backend: kamu.backends.SuomiFiBackend

This service doesn't really care about the authentication protocol as it only uses the environment variables
provided by the web server's authentication modules. You can check default variable names from the common settings,
and override them as needed in the local settings.

Login, registration and linking identifiers
-------------------------------------------

Remote login backends support login, registration and linking identifiers, depending on how they are called.

  * *Login* just tries to authenticate user with the given identifier.
  * *Create user* is the registration process. It creates a new user identity, if the identifier is not found in the
    database, otherwise it just logs user in.
  * *Link identifier* links new identifier to the current user.

These methods are defined in the authentication views.

ShibbolethLocalBackend uses the *create user* method instead of *login*. Other backends require that the invitation key
has been verified and saved to the session, before *create user* is allowed.

Logout
------

Remote logout paths for the backends are defined in the local settings. When logging out, local session is always
ended and user is redirected to remote login path.

If a user has logged in with multiple remote login methods (e.g. when linking identifiers), they are shown a reminder
to clear their session information, before redirecting to the remote logout path. This is because remote logout with
SAML2 and OIDC does not always return user to the application.

mod_auth_openidc does not support multiple simultaneous logins, so if remote login paths are defined and user is
linking remote identifier using OIDC, they are first redirected to logout path.
