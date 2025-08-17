import pytest
from django.urls import reverse
from django.contrib.auth import get_user_model
from . import factories
from passkey import backends

UserMode = get_user_model()

@pytest.mark.backend
@pytest.mark.django_db
class TestPasskeyModelBackend:
  authenticate_begin_url = reverse('passkey:begin_passkey_authentication')

  @pytest.mark.parametrize([
    'has_instance',
  ], [
    (True, ),
    (False, ),
  ], ids=[
    'has-instance',
    'does-not-have-instance',
  ])
  def test_update_passkey_session(self, mocker, rf, get_users, has_instance):
    if has_instance:
      _, user = get_users
      passkey = factories.PasskeyFactory(
        user=user,
        name='dummy-key',
        platform='Microsoft',
        credential_id='test-id',
        token='sample-token',
      )
      mocker.patch.object(passkey, 'get_platform', return_value='Microsoft')
      checker_passkey  = lambda data: data['use_passkey']
      checker_name     = lambda data: data['name'] == passkey.name
      checker_id       = lambda data: data['id'] == str(passkey.pk)
      checker_platform = lambda data: data['platform'] == passkey.platform
      checker_xpf      = lambda data: data['cross_platform']
      checker_output   = lambda user: isinstance(user, UserMode)
    else:
      passkey = None
      checker_passkey  = lambda data: not data['use_passkey']
      checker_name     = lambda data: data['name'] is None
      checker_id       = lambda data: data['id'] is None
      checker_platform = lambda data: data['platform'] is None
      checker_xpf      = lambda data: data['cross_platform'] is None
      checker_output   = lambda user: user is None
    request = rf.post(self.authenticate_begin_url, data={})
    request.session = {}
    instance = backends.PasskeyModelBackend()
    estimated = instance.update_passkey_session(request, instance=passkey)
    data = request.session['passkey']

    assert checker_passkey(data)
    assert checker_name(data)
    assert checker_id(data)
    assert checker_platform(data)
    assert checker_xpf(data)
    assert checker_output(estimated)

  def test_no_request_instance_in_authenticate(self, get_users):
    raw_passwd, user = get_users
    instance = backends.PasskeyModelBackend()
    err_msg = '`request` is required for passkey.backends.PasskeyModelBackend.'

    with pytest.raises(Exception) as ex:
      instance.authenticate(request=None, username=user.username, password=raw_passwd)

    assert err_msg == ex.value.args[0]

  def test_no_passkey_data_in_authenticate(self, rf):
    instance = backends.PasskeyModelBackend()
    params = {
      'username': '',
      'password': '',
    }
    request = rf.post(self.authenticate_begin_url, data=params)
    err_msg = '`passkey` is required in request.POST.'

    with pytest.raises(Exception) as ex:
      instance.authenticate(request=request, **params)

    assert err_msg == ex.value.args[0]

  def test_valid_login_using_username_and_password_in_authenticate(self, rf, get_users):
    raw_passwd, user = get_users
    instance = backends.PasskeyModelBackend()
    request = rf.post(self.authenticate_begin_url, data={})
    request.session = {}
    user = instance.authenticate(request=request, username=user.username, password=raw_passwd)

    assert user is not None
    assert not request.session['passkey']['use_passkey']

  def test_valid_login_using_passkey_in_authenticate(self, mocker, rf, get_users):
    _, user = get_users
    passkey = factories.PasskeyFactory(
      user=user,
      name='test-key',
      platform='Microsoft',
      credential_id='dummy-id',
      token='test-token',
    )
    mocker.patch.object(passkey, 'get_platform', return_value='Apple')
    mocker.patch('passkey.backends.Passkey.authenticate_complete', return_value=passkey)
    params = {
      'username': '',
      'password': '',
      'passkey': 'dummy-passkey',
    }
    request = rf.post(self.authenticate_begin_url, data=params)
    request.session = {}
    instance = backends.PasskeyModelBackend()
    logged_in_user = instance.authenticate(request=request)

    assert logged_in_user is not None
    assert isinstance(logged_in_user, UserMode)
    assert request.session['passkey']['use_passkey']
    assert request.session['passkey']['name'] == passkey.name
    assert request.session['passkey']['id'] == str(passkey.pk)
    assert request.session['passkey']['platform'] == passkey.platform
    assert not request.session['passkey']['cross_platform']

  @pytest.fixture(params=['empty-username', 'empty-password', 'no-data'])
  def get_backend_input(self, request, rf, get_users):
    raw_passwd, user = get_users
    patterns = {
      'empty-username': {'username': '', 'password': raw_passwd, 'passkey': ''},
      'empty-password': {'username': user.email, 'password': '', 'passkey': ''},
      'no-data': {'username': '', 'password': '', 'passkey': ''},
    }
    key = request.param
    data = patterns[key]
    # Create output values
    req = rf.post(self.authenticate_begin_url, data=data)
    params = {
      'username': data['username'],
      'password': data['password'],
    }

    return req, params

  def test_invalid_login_in_authenticate(self, get_backend_input):
    request, params = get_backend_input
    instance = backends.PasskeyModelBackend()
    user = instance.authenticate(request=request, **params)

    assert user is None