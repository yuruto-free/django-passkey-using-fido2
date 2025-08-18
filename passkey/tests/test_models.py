import pytest
import uuid
from base64 import urlsafe_b64encode
from django.db.utils import IntegrityError
from django.urls import reverse
from passkey import models
from . import factories

@pytest.fixture
def mock_fido2server(mocker):
  class _AuthData:
    def __init__(self):
      self.credential_data = bytes('test-cred', encoding='utf-8')

  class DummyServer:
    def __init__(self, *args, **kwargs):
      pass
    def register_begin(self, *args, **kwargs):
      data = {'id': 'sample', 'publicKey': {'challenge': 'test'}}
      state = {'result': 'ok', 'detail': 'none'}

      return data, state
    def register_complete(self, *args, **kwargs):
      return _AuthData()
    def authenticate_begin(self, *args, **kwargs):
      return self.register_begin(*args, **kwargs)
    def authenticate_complete(self, *args, **kwargs):
      return None

  mocker.patch('passkey.models.Passkey.get_server', return_value=DummyServer())

  return mocker

class DummyModel:
  def __init__(self, pk_type):
    from django.db import models as DjangoModels

    class _Integer:
      def __init__(self):
        self.pk = DjangoModels.IntegerField()

    class _UUID:
      def __init__(self):
        self.pk = DjangoModels.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    class _Other:
      def __init__(self):
        self.pk = DjangoModels.CharField('Other', max_length=128)

    # Main routine
    patterns = {
      'int': _Integer(),
      'uuid': _UUID(),
    }
    self._meta = patterns.get(pk_type, _Other())

@pytest.mark.model
@pytest.mark.django_db
class TestGlobalFunctions:
  @pytest.mark.parametrize([
    'pk_type',
    'value',
  ], [
    ('int', 3),
    ('uuid', uuid.uuid4()),
    ('str', 'hoge'),
    ('float', 3.14),
  ], ids=[
    'integer',
    'uuid',
    'string',
    'float',
  ])
  def test_pk_bytes(self, pk_type, value):
    patterns = {
      'int': lambda pk: pk.to_bytes(8),
      'uuid': lambda pk: pk.bytes,
    }
    convertor = patterns.get(pk_type, lambda pk: str(pk).encode('utf-8'))
    expected = convertor(value)
    estimated = models._pk_bytes(value)

    assert expected == estimated

  @pytest.mark.parametrize([
    'data_type',
    'value',
  ], [
    ('int', b'\x00\x00\x00\x00\x00\x00\x00\x03'),
    ('uuid', uuid.uuid4().bytes),
    ('str', b'hoge'),
    ('float', str(3.14).encode('utf-8')),
  ], ids=[
    'integer',
    'uuid',
    'string',
    'float',
  ])
  def test_pk_value(self, mocker, data_type, value):
    mocker.patch('passkey.models.get_user_model', return_value=DummyModel(data_type))
    patterns = {
      'int': lambda data: int.from_bytes(data),
      'uuid': lambda data: uuid.UUID(bytes=data),
    }
    convertor = patterns.get(data_type, lambda data: data.decode('utf-8'))
    expected = convertor(value)
    estimated = models._pk_value(value)

    assert expected == estimated

@pytest.mark.model
@pytest.mark.django_db
class TestPasskey:
  register_url = reverse('passkey:register_passkey')
  authenticate_begin_url = reverse('passkey:begin_passkey_authentication')

  def test_valid_constraints(self, get_users):
    _, user = get_users
    other = factories.UserFactory()
    credential_id = 'same-credential-id'
    factories.PasskeyFactory(user=user, credential_id=credential_id)

    try:
      models.Passkey.objects.create(
        user=other,
        name='test-key',
        platform='Apple',
        credential_id=credential_id,
        token='test-token',
        is_enabled=True,
      )
    except Exception as ex:
      pytest.fail(f'Unexpected Error: {ex}')

  def test_invalid_constraints(self, get_users):
    _, user = get_users
    credential_id = 'same-credential-id'
    factories.PasskeyFactory(user=user, credential_id=credential_id)
    err_msg = 'UNIQUE constraint failed'

    with pytest.raises(IntegrityError) as ex:
      models.Passkey.objects.create(
        user=user,
        name='test-key',
        platform='Apple',
        credential_id=credential_id,
        token='test-token',
        is_enabled=True,
      )

    assert err_msg in ex.value.args[0]

  def test_str_method(self):
    instance = factories.PasskeyFactory()
    expected = f'{instance.user}({instance.platform})'
    estimated = str(instance)

    assert expected == estimated

  @pytest.mark.parametrize([
    'is_same',
    'expected',
  ], [
    (True, True),
    (False, False),
  ], ids=[
    'is-same-user',
    'is-not-same-user',
  ])
  def test_has_update_permission(self, get_users, is_same, expected):
    _, user = get_users

    if is_same:
      target = user
    else:
      target = factories.UserFactory()
    instance = factories.PasskeyFactory(user=user)
    can_update = instance.has_update_permission(target)

    assert can_update == expected

  @pytest.mark.parametrize([
    'is_same',
    'is_enabled',
    'expected',
  ], [
    (True, False, True),
    (False, False, False),
    (True, True, False),
    (False, True, False),
  ], ids=[
    'is-same-user-and-is-not-enabled',
    'is-not-same-user-and-is-not-enabled',
    'is-same-user-and-is-enabled',
    'is-not-same-user-and-is-enabled',
  ])
  def test_has_delete_permission(self, get_users, is_same, is_enabled, expected):
    _, user = get_users

    if is_same:
      target = user
    else:
      target = factories.UserFactory()
    instance = factories.PasskeyFactory(user=user, is_enabled=is_enabled)
    can_delete = instance.has_delete_permission(target)

    assert can_delete == expected

  @pytest.mark.parametrize([
    'is_enabled',
    'expected',
  ], [
    (False, True),
    (True, False),
  ], ids=[
    'is-enabled',
    'is-not-enabled',
  ])
  def test_toggle_passkey_status(self, get_users, is_enabled, expected):
    _, user = get_users
    instance = factories.PasskeyFactory(user=user, is_enabled=is_enabled)
    instance.toggle_passkey_status()

    assert instance.is_enabled == expected

  @pytest.mark.parametrize([
    'callable_server_id',
    'callable_server_name',
  ], [
    (False, False),
    (True, False),
    (False, True),
    (True, True),
  ], ids=[
    'cannot-call-both-id-and-name',
    'can-call-server-id',
    'can-call-server-name',
    'can-call-both-id-and-name',
  ])
  def test_get_server(self, settings, rf, callable_server_id, callable_server_name):
    from fido2.server import Fido2Server
    # Set server id
    if callable_server_id:
      expected_server_id = 'callable-server-id'
      settings.FIDO_SERVER_ID = lambda request: expected_server_id
    else:
      expected_server_id = 'test-server-id'
      settings.FIDO_SERVER_ID = expected_server_id
    # Set server name
    if callable_server_name:
      expected_server_name = 'callable-server-name'
      settings.FIDO_SERVER_NAME = lambda request: expected_server_name
    else:
      expected_server_name = 'test-server-name'
      settings.FIDO_SERVER_NAME = expected_server_name
    # Call target method
    request = rf.get(self.register_url)
    server = models.Passkey.get_server(request)

    assert isinstance(server, Fido2Server)

  @pytest.mark.parametrize([
    'user_agent',
    'expected',
  ], [
    # Apple
    ('Mozilla/5.0 (iPhone; CPU iPhone OS 5_1 like Mac OS X) AppleWebKit/567.89 (KHTML, like Gecko) Opera/123.4.5', 'Apple'),
    ('Mozilla/5.0 (iPad; CPU OS 16_5 like Mac OS X) AppleWebKit/567.89 (KHTML, like Gecko) Version/16.5 Opera/123.4.5', 'Apple'),
    ('Mozilla/5.0 (iPod touch; CPU iPhone OS 12_0 like Mac OS X) AppleWebKit/567.89 (KHTML, like Gecko) Version/16.5 Opera/123.4.5', 'Apple'),
    ('AppleTV3,1/6.0.1 (10A831)', 'Apple'),
    ('Mozilla/5.0 (XXX; CPU OS 5_1 like Mac OS X) AppleWebKit/567.89 (KHTML, like Gecko) Version/16.5 Opera/123.4.5', 'Apple'),
    ('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_6_8) AppleWebKit/567.89 (KHTML, like Gecko) Version/16.5 Opera/123.4.5', 'Apple'),
    ('Mozilla/5.0 (XXX; CPU YYY 1_2_3 like ZZZ) AppleWebKit/567.89 (KHTML, like Gecko) CriOS/139.0.1.2 Opera/123.4.5', 'Apple'),
    ('Mozilla/5.0 (XXX; CPU YYY 12_12 like ZZZ) AppleWebKit/567.89 (KHTML, like Gecko) Version/16.5 Mobile/15E148 Safari/623.0', 'Apple'),
    # Amazon
    ('Mozilla/5.0 (Linux; U; Android 5.1.2; en-us; Kindle Fire Build/GINGERBREAD) AppleWebKit/567.89 (KHTML, like Gecko) Version/16.5 Mobile Safari/623.0', 'Amazon'),
    ('Mozilla/5.0 (Linux; U; Android 5.1.2; en-us; Silk/1.0.146.3-Gen4_12000410) AppleWebKit/567.89 (KHTML, like Gecko) Version/16.5 Mobile Safari/623.0 Silk-Accelerated=true', 'Amazon'),
    ('fuboTV/2.0.2 (Linux;Android 5.1.2; AFTT Build/LVY48F) FuboPlayer/1.0.2.4', 'Amazon'),
    ('SPMC/16.3-0 (Linux; Android 5.1.2; AFTM Build/LVY48F) Kodi_Fork_SPMC/1.0 Android/5.1.2', 'Amazon'),
    ('Kodi/16.1-2 (Linux; Android 5.1.2; AFTB Build/LVY48F) Android/5.1.2 Sys_CPU/armv7l', 'Amazon'),
    ('Mozilla/5.0 (Linux; Android 5.1.2; AFTS Build/LVY48F) AppleWebKit/567.89 (KHTML, like Gecko) Chrome/123.4.5.6 Mobile Safari/623.0', 'Amazon'),
    # Windows
    ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/567.89 (KHTML, like Gecko) Chrome/123.4.5.6 Safari/623.0', 'Microsoft'),
    ('Mozilla/5.0 (compatible; MSIE 9.0; Windows Phone OS 10.5; Android 4.2.1; Trident/5.0; IEMobile/9.0; SAMSUNG; SGH-i917)', 'Microsoft'),
    ('Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2; ARM; Trident/6.0)', 'Microsoft'),
    # Android
    ('Mozilla/5.0 (Linux; Android 11) AppleWebKit/567.89 (KHTML, like Gecko) Chrome/123.4.5.6 Mobile Safari/623.0', 'Google'),
    ('Mozilla/5.0 (X11; Linux x86_64)  AppleWebKit/567.89 (KHTML, like Gecko) Chrome/123.4.5.6 Safari/623.0', 'Google'),
    ('Mozilla/5.0 (X11; CrOS x86_64 1024.32.8) AppleWebKit/567.89 (KHTML, like Gecko) Chrome/123.4.5.6 Safari/623.0', 'Google'),
    # Unknown
    ('Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:15.0) Gecko/20100101 Chrome/123.4.5.6', 'Unknown'),
  ], ids=[
    # Apple
    'iPhone-iOS',
    'iPad-iOS',
    'iPod-iOS',
    'AppleTV',
    'iOS',
    'Mac-OS-X',
    'Chrome-Mobile-iOS',
    'Safari',
    # Amazon
    'Kindle-Fire',
    'Kindle-Silk',
    'Fire-TV(AFTT)',
    'Fire-TV(AFTM)',
    'Fire-TV(AFTB)',
    'Fire-TV(AFTS)',
    # Windows
    'Windows-PC',
    'Windows-Phone',
    'Windows-RT',
    # Android
    'Normal-Android',
    'PC-site-Android',
    'Chrome-OS',
    # Unknown
    'Unknown',
  ])
  def test_get_platform(self, rf, user_agent, expected):
    request = rf.get('/', HTTP_USER_AGENT=user_agent)
    platform = models.Passkey.get_platform(request)

    assert expected == platform

  def test_get_credentials(self, mocker, get_users):
    mocker.patch('passkey.models.AttestedCredentialData', side_effect=['a', 'b', 'c'])
    _, user = get_users
    passkeys = factories.PasskeyFactory.create_batch(3, user=user)
    # Call target method
    credentials = models.Passkey.get_credentials(user)

    assert len(passkeys) == len(credentials)

  def test_register_begin(self, rf, mock_fido2server, get_users):
    _ = mock_fido2server
    _, user = get_users
    request = rf.get(self.register_url)
    request.session = {}
    request.user = user
    estimated = models.Passkey.register_begin(request)

    assert all([key in ['id', 'publicKey'] for key in estimated.keys()])
    assert estimated['id'] == 'sample'
    assert estimated['publicKey'] == {'challenge': 'test'}
    assert 'fido2_state' in request.session
    assert request.session['fido2_state'] == {'result': 'ok', 'detail': 'none'}

  def test_valid_register_complete(self, rf, mock_fido2server, get_users):
    mocker = mock_fido2server
    mocker.patch('passkey.models.Passkey.get_platform', return_value='Microsoft')
    _, user = get_users
    params = {
      'id': 'someone-0xabc123',
      'key_name': 'test-passkey',
    }
    request = rf.post(self.register_url, data=params, content_type='application/json')
    request.session = {'fido2_state': {'result': 'ok', 'detail': 'none'}}
    request.user = user
    # Call target method
    status_code, message = models.Passkey.register_complete(request)
    instance = models.Passkey.objects.get(user=user, credential_id=params['id'])

    assert status_code == 200
    assert message == 'Complete the registeration.'
    assert instance.name == params['key_name']
    assert instance.is_enabled
    assert instance.platform == 'Microsoft'

  @pytest.mark.parametrize([
    'pattern',
  ], [
    ('no-session-data', ),
    ('has-error', ),
  ], ids=lambda xs: str(xs))
  def test_invalid_register_complete(self, rf, mock_fido2server, get_users, pattern):
    mocker = mock_fido2server
    _, user = get_users
    params = {
      'id': 'someone-0xabc123',
      'key_name': 'test-invalid-passkey',
    }
    request = rf.post(self.register_url, data=params)
    # Customize data based on pattern
    if pattern == 'has-error':
      request.session = {'fido2_state': {'result': 'ok', 'detail': 'none'}}
      mocker.patch('passkey.models.Passkey.get_platform', side_effect=Exception('Error'))
      status_code = 500
      err_msg = 'Error on server, please try again later.'
    else:
      request.session = {}
      status_code = 401
      err_msg = 'FIDO Status can’t be found, please try again.'
    # Call target method
    status_code, message = models.Passkey.register_complete(request)

    assert status_code == status_code
    assert message == err_msg

  @pytest.mark.parametrize([
    'is_authenticated',
  ], [
    (True, ),
    (False, ),
  ], ids=[
    'is-authenticated',
    'is-not-authenticated',
  ])
  def test_authenticate_begin(self, rf, mock_fido2server, get_users, is_authenticated):
    class DummyUser:
      def __init__(self):
        self.is_authenticated = False

    mocker = mock_fido2server
    mocker.patch('passkey.models.Passkey.get_credentials', return_value=['a', 'b'])
    _, user = get_users
    request = rf.get(self.authenticate_begin_url)
    if is_authenticated:
      request.user = user
    else:
      request.user = DummyUser()
    request.session = {}
    # Call target method
    estimated = models.Passkey.authenticate_begin(request)

    assert estimated == {'id': 'sample', 'publicKey': {'challenge': 'test'}}
    assert request.session['fido2_state'] == {'result': 'ok', 'detail': 'none'}

  def test_valid_authenticate_complete(self, rf, mock_fido2server, get_users):
    mocker = mock_fido2server
    mocker.patch('passkey.models.AttestedCredentialData', return_value='sample')
    mocker.patch('passkey.models.Passkey.get_platform', return_value='Microsoft')
    _, user = get_users
    credential_id = 'test-id-for-valid-authenticate-complete'
    _ = factories.PasskeyFactory(
      user=user,
      credential_id=credential_id,
      is_enabled=True,
      platform='Unknown',
    )
    params = {
      'passkey': {
        'response': {
          'userHandle': urlsafe_b64encode(models._pk_bytes(user.pk)),
        },
        'id': credential_id,
      },
    }
    mocker.patch('passkey.models.json.loads', return_value=params['passkey'])
    request = rf.post('/', data=params)
    request.session = {'fido2_state': {'result': 'ok', 'detail': 'none'}}
    # Call target method
    estimated = models.Passkey.authenticate_complete(request)
    instance = models.Passkey.objects.get(user=user, credential_id=credential_id, is_enabled=True)

    assert estimated is not None
    assert estimated.pk == instance.pk

  def test_invalid_credID_in_authenticate_complete(self, mocker, rf, get_users):
    _, user = get_users
    credential_id = 'invalid-id-of-authenticate-complete'
    params = {
      'passkey': {
        'response': {
          'userHandle': urlsafe_b64encode(models._pk_bytes(user.pk)),
        },
        'id': credential_id,
      },
    }
    mocker.patch('passkey.models.json.loads', return_value=params['passkey'])
    request = rf.post('/', data=params)
    # Call target method
    estimated = models.Passkey.authenticate_complete(request)

    assert estimated is None

  @pytest.fixture(params=['value-error', 'database-error', 'has-exception'])
  def set_exception(self, request, mock_fido2server):
    def inner(user):
      key = request.param
      mocker = mock_fido2server

      if key == 'value-error':
        mocker.patch('passkey.models.Passkey.objects.get', return_value=factories.PasskeyFactory(user=user))
        mocker.patch('passkey.models.AttestedCredentialData', side_effect=ValueError('Value Error'))
      elif key == 'database-error':
        mocker.patch('passkey.models.Passkey.objects.get', side_effect=models.Passkey.DoesNotExist('Database Error'))
      else:
        mocker.patch('passkey.models.Passkey.objects.get', return_value=factories.PasskeyFactory(user=user))
        mocker.patch('passkey.models.AttestedCredentialData', side_effect=Exception('Error'))

      return mocker

    return inner

  def test_raise_exception_in_authenticate_complete(self, rf, get_users, set_exception):
    _, user = get_users
    params = {
      'passkey': {
        'response': {
          'userHandle': urlsafe_b64encode(models._pk_bytes(user.pk)),
        },
        'id': 'sample-id',
      },
    }
    mocker = set_exception(user)
    mocker.patch('passkey.models.json.loads', return_value=params['passkey'])
    request = rf.post('/', data=params)
    # Call target method
    estimated = models.Passkey.authenticate_complete(request)

    assert estimated is None