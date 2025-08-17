## django-passkey using FIDO2 library
It's an extension of `Django ModelBackend` to support passkey.

A passkey here is an extension to Web Authentication API which will allow the user to login to the specific web site using another device authentication.

## How to use this application
1. In your `settings.py`, add this application to your `INSTALLED_APPS`.

    ```python
    INSTALLED_APPS = [
      '...',
      'passkey',
      '...',
    ]
    ```

1. Execute the following command to collect static files.

    ```bash
    python manage.py collectstatic
    ```

1. Run migrate command.

    ```bash
    python manage.py migrate
    ```

1. Add the following variables related as this application to your `settings.py` file.

    ```python
    AUTHENTICATION_BACKENDS = [
      # Use the following backend instead of `django.contrib.auth.backends.ModelBackend`
      'passkey.backends.PasskeyModelBackend',
    ]
    # Add `FIDO_SERVER_ID` and `FIDO_SERVER_NAME`
    # Its `FIDO_SERVER_ID` here is relying party ID and in general, the full domain of your project is set.
    FIDO_SERVER_ID = 'localhost'
    FIDO_SERVER_NAME = 'Test server'
    # Add key attachment type
    import passkey
    KEY_ATTACHMENT = None # Options: None, passkey.Attachment.CROSS_PLATFORM, or passkey.Attachment.PLATFORM
    ```

    In the above setting, there are three patterns as `KEY_ATTACHMENT`.

    | Pattern | Detail |
    | :---- | :---- |
    | `None` | Allow all devices. |
    | `passkey.Attachment.CROSS_PLATFORM` | Allow only roaming devices like security keys. |
    | `passkey.Attachment.PLATFORM` | Allow only devices linked to a platform like TouchID and Windows Hello. |

    For the first trial, I think that you starts with `None` preferably.

    In addition, `FIDO_SERVER_ID` and `FIDO_SERVER_NAME` can set a callable function with `request` argument.

    ```python
    # Example
    FIDO_SERVER_ID = lambda request: request.get_host()
    ```

1. Update login/logout variables in your `settings.py`. [Note] redirect url is set based on your application structure.

    ```python
    LOGIN_URL = 'passkey:login'
    LOGIN_REDIRECT_URL = 'your-app:index'  # Customize it based on your project
    LOGOUT_URL = 'passkey:logout'
    LOGOUT_REDIRECT_URL = 'your-app:index' # Customize it based on your project
    ```

1. Add passkey to `urls.py`.

    ```python
    from django.urls import path, include

    urlpatterns = [
      '...',
      path('passkey/', include('passkey.urls')),
      '...',
    ]
    ```

1. Somewhere add `passkey:passkey_list` and `passkey:login` to your project.

    ```html
    <!-- Passkey list page -->
    <a href="{% url 'passkey:passkey_list' %}">Registered passkeys</a>
    <!-- Login page -->
    <a href="{% url 'passkey:login' %}">Login with passkey</a>
    ```

## Session type for login pattern
In this application, when the user is logged in, passkey information is set to `request.session['passkey']`.
The detail is shown below.

| Element          | Username/Password login | Passkey login |
| :----            | :----   | :---- |
| `use_passkey`    | `False` | `True` |
| `name`           | `None`  | The given key name when the user registered the passkey. |
| `id`             | `None`  | Primary key (UUID) of `passkey.models.Passkey` instance |
| `platform`       | `None`  | Platform name which is one of `Apple`, `Amazon`, `Microsoft`, `Google`, and `Unknown`. |
| `cross_platform` | `None`  | `True/False`, If `True`, the user used a key from another platform, which means there is no key local to the device used to login. |