import pytest
from . import factories

@pytest.fixture(scope='session', autouse=True)
def django_db_setup(django_db_setup):
  pass

@pytest.fixture(autouse=True)
def setup_django(settings, tmp_path):
  # Create base.html
  target_path = tmp_path / 'base.html'
  settings.TEMPLATES[0]['DIRS'] = [tmp_path]
  contents = [
    '<!DOCTYPE html>',
    '<html lang="en"><head><title>Test passkey</title>{% block header %}{% endblock %}</head>',
    '<body><main><div class="container">{% block content %}{% endblock %}</div></main></body></html>',
  ]
  target_path.write_text('\n'.join(contents))
  # Define relevant variables for settings.py
  settings.LOGIN_URL = 'passkey:login'
  settings.LOGIN_REDIRECT_URL = 'passkey:passkey_list'
  settings.LOGOUT_URL = 'passkey:logout'
  settings.LOGOUT_REDIRECT_URL = 'passkey:login'

@pytest.fixture(scope='module')
def get_superuser(django_db_blocker):
  with django_db_blocker.unblock():
    user = factories.UserFactory(is_staff=True, is_superuser=True)

  return user

@pytest.fixture(scope='module')
def get_normal_user(django_db_blocker):
  with django_db_blocker.unblock():
    user = factories.UserFactory()

  return user

@pytest.fixture(scope='module', params=['superuser', 'normaluser'])
def get_users(django_db_blocker, request, get_superuser, get_normal_user):
  patterns = {
    'superuser': get_superuser,
    'normaluser': get_normal_user,
  }
  raw_passwd = 'test123@passwd'
  user = patterns[request.param]

  with django_db_blocker.unblock():
    user.set_password(raw_passwd)
    user.save()

  return raw_passwd, user