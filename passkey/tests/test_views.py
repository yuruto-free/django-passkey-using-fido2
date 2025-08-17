import json
import pytest
from django.urls import reverse
from . import (
  status,
  factories,
  SoftWebauthnDevice,
)
from passkey import views, models

@pytest.mark.view
@pytest.mark.django_db
class TestPasskeyView:
  list_view_url = reverse('passkey:passkey_list')
  update_view_url = lambda _self, pk: reverse('passkey:update_passkey_status', kwargs={'pk': pk})
  delete_view_url = lambda _self, pk: reverse('passkey:delete_passkey', kwargs={'pk': pk})

  def test_get_access_to_listview(self, get_users, client):
    _, user = get_users
    client.force_login(user)
    response = client.get(self.list_view_url)

    assert response.status_code == status.HTTP_200_OK

  def test_queryset_method_in_listview(self, rf, get_users):
    _, user = get_users
    others = factories.UserFactory.create_batch(3)
    # Create passkey instances
    _ = factories.PasskeyFactory(user=user)
    _ = factories.PasskeyFactory(user=user, is_enabled=False)
    _ = factories.PasskeyFactory(user=others[0])
    _ = factories.PasskeyFactory(user=others[0], is_enabled=False)
    _ = factories.PasskeyFactory(user=others[1])
    _ = factories.PasskeyFactory(user=others[2])
    _ = factories.PasskeyFactory(user=others[2], is_enabled=False)
    # Call get_queryset method
    request = rf.get(self.list_view_url)
    request.user = user
    view = views.PasskeyListView()
    view.setup(request)
    queryset = view.get_queryset()

    assert queryset.count() == 2

  def test_get_access_to_updateview(self, get_users, client):
    _, user = get_users
    instance = factories.PasskeyFactory(user=user)
    url = self.update_view_url(instance.pk)
    client.force_login(user)
    response = client.get(url)

    assert response.status_code == status.HTTP_405_METHOD_NOT_ALLOWED

  @pytest.mark.parametrize([
    'is_enabled',
    'expected',
  ], [
    (True, False),
    (False, True),
  ], ids=[
    'from-enable-to-disable',
    'from-disable-to-enable',
  ])
  def test_post_access_to_updatepview(self, get_users, client, is_enabled, expected):
    _, user = get_users
    client.force_login(user)
    old_obj = factories.PasskeyFactory(user=user, is_enabled=is_enabled)
    url = self.update_view_url(old_obj.pk)
    response = client.post(url, data={})
    instance = models.Passkey.objects.get(pk=old_obj.pk)

    assert response.status_code == status.HTTP_302_FOUND
    assert response['Location'] == self.list_view_url
    assert instance.is_enabled == expected

  def test_invalid_post_request_in_updatepview(self, get_users, client):
    _, user = get_users
    other = factories.UserFactory()
    client.force_login(user)
    other_member_instance = factories.PasskeyFactory(user=other)
    url = self.update_view_url(other_member_instance.pk)
    response = client.post(url, data={})

    assert response.status_code == status.HTTP_403_FORBIDDEN

  def test_get_access_to_deleteview(self, get_users, client):
    _, user = get_users
    instance = factories.PasskeyFactory(user=user, is_enabled=False)
    url = self.delete_view_url(instance.pk)
    client.force_login(user)
    response = client.get(url)

    assert response.status_code == status.HTTP_405_METHOD_NOT_ALLOWED

  def test_post_access_to_deleteview(self, get_users, client):
    _, user = get_users
    instance = factories.PasskeyFactory(user=user, is_enabled=False)
    url = self.delete_view_url(instance.pk)
    client.force_login(user)
    response = client.post(url)
    queryset = models.Passkey.objects.filter(pk__in=[instance.pk])

    assert response.status_code == status.HTTP_302_FOUND
    assert queryset.count() == 0

  @pytest.mark.parametrize([
    'is_same',
    'is_enabled',
  ], [
    (True, True),
    (False, False),
  ], ids=[
    'is-enable',
    'the-other-user',
  ])
  def test_invalid_post_request_in_deleteview(self, get_users, client, is_same, is_enabled):
    _, user = get_users
    other = factories.UserFactory()
    target = user if is_same else other
    instance = factories.PasskeyFactory(user=target, is_enabled=is_enabled)
    url = self.delete_view_url(instance.pk)
    client.force_login(user)
    response = client.post(url)
    queryset = models.Passkey.objects.filter(pk__in=[instance.pk])

    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert queryset.count() == 1

@pytest.mark.view
@pytest.mark.django_db
class TestPasskeyAuthView:
  register_url = reverse('passkey:register_passkey')
  authenticate_begin_url = reverse('passkey:begin_passkey_authentication')
  login_url = reverse('passkey:login')
  logout_url = reverse('passkey:logout')

  def test_passkey_registration(self, get_users, client):
    _, user = get_users
    client.force_login(user)
    # Passkey registration
    register_response = client.get(self.register_url, secure=True)
    jsonData = json.loads(register_response.content)
    jsonData['publicKey']['challenge'] = jsonData['publicKey']['challenge'].encode('ascii')
    target_id = jsonData['publicKey']['rp']['id']
    soft_device = SoftWebauthnDevice()
    credentials = soft_device.create(jsonData, f'https://{target_id}')
    credentials['key_name'] = 'test-device'
    # Passkey registration completation
    complete_response = client.post(
      self.register_url,
      data=json.dumps(credentials),
      headers={'USER_AGENT': ''},
      HTTP_USER_AGENT='',
      content_type='application/json',
      secure=True,
    )

    try:
      output = json.loads(complete_response.content)
    except Exception as ex:
      pytest.fail(f'Unexpected Error: {ex}')
    instance = models.Passkey.objects.get(user=user, credential_id=credentials['id'])

    assert register_response.status_code == status.HTTP_200_OK
    assert complete_response.status_code == status.HTTP_200_OK
    assert 'message' in output.keys()
    assert output['message'] == 'Complete the registeration.'
    assert instance.name == credentials['key_name']

  def test_set_key_name_automatically(self, get_users, client):
    _, user = get_users
    client.force_login(user)
    # Passkey registration
    register_response = client.get(self.register_url, secure=True)
    jsonData = json.loads(register_response.content)
    jsonData['publicKey']['challenge'] = jsonData['publicKey']['challenge'].encode('ascii')
    target_id = jsonData['publicKey']['rp']['id']
    soft_device = SoftWebauthnDevice()
    credentials = soft_device.create(jsonData, f'https://{target_id}')
    # Passkey registration completation
    user_agent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 17_3) AppleWebKit/765.4.32 (KHTML, like Gecko) Version/17.3 Safari/765.4.32'
    complete_response = client.post(
      self.register_url,
      data=json.dumps(credentials),
      HTTP_USER_AGENT=user_agent,
      content_type='application/json',
      secure=True,
    )

    try:
      output = json.loads(complete_response.content)
    except Exception as ex:
      pytest.fail(f'Unexpected Error: {ex}')
    instance = models.Passkey.objects.get(user=user, credential_id=credentials['id'])

    assert register_response.status_code == status.HTTP_200_OK
    assert complete_response.status_code == status.HTTP_200_OK
    assert 'message' in output.keys()
    assert output['message'] == 'Complete the registeration.'
    assert instance.name == 'Apple'

  def test_invalid_complete_request_without_session(self, get_users, client):
    _, user = get_users
    client.force_login(user)
    credentials = {
      'key_name': 'test-key',
    }
    response = client.post(
      self.register_url,
      data=json.dumps(credentials),
      headers={'USER_AGENT': ''},
      HTTP_USER_AGENT='',
      content_type='application/json',
      secure=True,
    )

    try:
      output = json.loads(response.content)
    except Exception as ex:
      pytest.fail(f'Unexpected Error: {ex}')

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert 'message' in output.keys()
    assert output['message'] == 'FIDO Status can’t be found, please try again.'

  def test_invalid_complete_request_with_error(self, mocker, get_users, client):
    _, user = get_users
    client.force_login(user)
    # Passkey registration
    register_response = client.get(self.register_url, secure=True)
    jsonData = json.loads(register_response.content)
    jsonData['publicKey']['challenge'] = jsonData['publicKey']['challenge'].encode('ascii')
    target_id = jsonData['publicKey']['rp']['id']
    soft_device = SoftWebauthnDevice()
    credentials = soft_device.create(jsonData, f'https://{target_id}')
    credentials['key_name'] = 'test-device'
    # Passkey registration completation
    mocker.patch('passkey.models.Passkey.get_server', side_effect=Exception('Error'))
    complete_response = client.post(
      self.register_url,
      data=json.dumps(credentials),
      headers={'USER_AGENT': ''},
      HTTP_USER_AGENT='',
      content_type='application/json',
      secure=True,
    )

    try:
      output = json.loads(complete_response.content)
    except Exception as ex:
      pytest.fail(f'Unexpected Error: {ex}')

    assert register_response.status_code == status.HTTP_200_OK
    assert complete_response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
    assert 'message' in output.keys()
    assert output['message'] == 'Error on server, please try again later.'

  def test_login_process_with_passkey(self, get_users, client):
    _, user = get_users
    client.force_login(user)
    # Passkey registration
    response = client.get(self.register_url, secure=True)
    jsonData = json.loads(response.content)
    jsonData['publicKey']['challenge'] = jsonData['publicKey']['challenge'].encode('ascii')
    target_id = jsonData['publicKey']['rp']['id']
    soft_device = SoftWebauthnDevice()
    credentials = soft_device.create(jsonData, f'https://{target_id}')
    credentials['key_name'] = 'test-device'
    # Passkey registration completation
    _ = client.post(
      self.register_url,
      data=json.dumps(credentials),
      headers={'USER_AGENT': ''},
      HTTP_USER_AGENT='',
      content_type='application/json',
      secure=True,
    )
    # Logout
    client.logout()
    # Login with passkey
    auth_begin_response = client.get(self.authenticate_begin_url, secure=True)
    jsonData = json.loads(auth_begin_response.content)
    jsonData['publicKey']['challenge'] = jsonData['publicKey']['challenge'].encode('ascii')
    target_id = jsonData['publicKey']['rpId']
    assertion = soft_device.get(jsonData, f'https://{target_id}')
    params = {
      'passkey': json.dumps(assertion),
      'username': '',
      'password': '',
    }
    login_response = client.post(
      self.login_url,
      data=params,
      headers={'USER_AGENT': ''},
      HTTP_USER_AGENT='',
      follow=True,
      secure=True,
    )
    passkey = client.session.get('passkey', {})

    assert auth_begin_response.status_code == status.HTTP_200_OK
    assert login_response.status_code == status.HTTP_200_OK
    assert passkey.get('use_passkey', False)
    assert passkey.get('name') == credentials['key_name']

  def test_logout_process(self, get_users, settings, client):
    _, user = get_users
    client.force_login(user)
    response = client.post(self.logout_url)

    assert response.status_code == status.HTTP_302_FOUND
    assert response['Location'] == reverse(settings.LOGOUT_REDIRECT_URL)