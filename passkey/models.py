import json
import logging
import uuid

from django.db import models
from django.conf import settings
from django.contrib.auth import get_user_model
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from base64 import urlsafe_b64encode
from fido2.server import Fido2Server
from fido2.utils import websafe_decode, websafe_encode
from fido2.webauthn import (
  PublicKeyCredentialRpEntity,
  AttestedCredentialData,
  ResidentKeyRequirement,
)
from user_agents.parsers import parse as ua_parse

def _pk_bytes(pk):
  if isinstance(pk, int):
    ret = pk.to_bytes(8)
  elif isinstance(pk, uuid.UUID):
    ret = pk.bytes
  else:
    ret = str(pk).encode('utf-8')

  return ret

def _pk_value(data):
  UserModel = get_user_model()
  field = UserModel._meta.pk

  if isinstance(field, models.IntegerField):
    ret = int.from_bytes(data)
  elif isinstance(field, models.UUIDField):
    ret = uuid.UUID(bytes=data)
  else:
    ret = data.decode('utf-8')

  return ret

class Passkey(models.Model):
  id = models.UUIDField(
    primary_key=True,
    default=uuid.uuid4,
    editable=False,
  )
  user = models.ForeignKey(
    settings.AUTH_USER_MODEL,
    verbose_name=_('User'),
    on_delete=models.CASCADE,
    related_name='passkeys',
  )
  name = models.CharField(
    _('Passkey name'),
    max_length=255,
  )
  platform = models.CharField(
    _('Platform'),
    max_length=255,
    default='',
  )
  credential_id = models.CharField(
    _('Credential ID'),
    max_length=255,
  )
  token = models.CharField(
    _('Token'),
    max_length=255,
    null=False,
    help_text=_('Attested credential data which is encoded by websafe-base64 string'),
  )
  is_enabled = models.BooleanField(
    _('Passkey status'),
    default=True,
  )
  date_joined = models.DateTimeField(
    _('Date joined'),
    auto_now_add=True,
  )
  last_used = models.DateTimeField(
    _('Last used'),
    null=True,
    default=None,
  )

  class Meta:
    verbose_name = _('passkey')
    verbose_name_plural = _('passkeys')
    constraints = [
      models.UniqueConstraint(fields=['user', 'credential_id'], name='passkey_unique_user_credential'),
    ]

  def __str__(self):
    return f'{self.user}({self.platform})'

  def has_update_permission(self, user):
    return self.user.pk == user.pk

  def has_delete_permission(self, user):
    return self.has_update_permission(user) and not self.is_enabled

  def toggle_passkey_status(self):
    self.is_enabled = not self.is_enabled

  @staticmethod
  def get_server(request=None):
    fido_server_id = getattr(settings, 'FIDO_SERVER_ID')
    fido_server_name = getattr(settings, 'FIDO_SERVER_NAME')
    # Get server id and server name
    server_id = fido_server_id(request) if callable(fido_server_id) else str(fido_server_id)
    server_name = fido_server_name(request) if callable(fido_server_name) else str(fido_server_name)
    # Get relying party and server
    relying_party = PublicKeyCredentialRpEntity(id=server_id, name=server_name)
    server = Fido2Server(relying_party)

    return server

  @staticmethod
  def get_platform(request):
    user_agent = ua_parse(request.META['HTTP_USER_AGENT'])
    device = user_agent.device.family
    os = user_agent.os.family
    browser = user_agent.browser.family

    if any([device in ['iPhone', 'iPad', 'iPod', 'AppleTV'], os in ['iOS', 'Mac OS X'], browser in ['Chrome Mobile iOS', 'Safari']]):
      platform = 'Apple'
    elif any([key in device for key in ['Kindle', 'AFTS', 'AFTB', 'AFTM', 'AFTT']]):
      platform = 'Amazon'
    elif 'Windows' in os:
      platform = 'Microsoft'
    elif any(['Android' in os, 'Linux' in os and 'Chrome' in browser, 'Chrome OS' in os]):
      platform = 'Google'
    else:
      platform = 'Unknown'

    return platform

  @staticmethod
  def get_credentials(user):
    tokens = Passkey.objects.filter(user=user).values_list('token', flat=True)
    credentials = [AttestedCredentialData(websafe_decode(token)) for token in tokens]

    return credentials

  @classmethod
  def register_begin(cls, request):
    user = request.user
    server = cls.get_server(request)
    authenticator_attachment = getattr(settings, 'KEY_ATTACHMENT', None)
    username = user.get_username()
    user_entity = {
      'id': urlsafe_b64encode(_pk_bytes(user.pk)),
      'name': username,
      'displayName': str(user),
    }
    credentials = cls.get_credentials(user)
    data, state = server.register_begin(
      user_entity,
      credentials,
      resident_key_requirement=ResidentKeyRequirement.PREFERRED,
      authenticator_attachment=authenticator_attachment,
    )
    options = dict(data)
    request.session['fido2_state'] = state

    return options

  @classmethod
  def register_complete(cls, request):
    logger = logging.getLogger(__name__)

    try:
      if 'fido2_state' not in request.session:
        status_code, message = 401, _('FIDO Status can’t be found, please try again.')
      else:
        server = cls.get_server(request)
        state = request.session.pop('fido2_state')
        data = json.loads(request.body)
        authenticator_data = server.register_complete(state, response=data)
        platform = cls.get_platform(request)
        # Create the passkey record
        cls.objects.create(
          user=request.user,
          name=data.get('key_name', platform),
          platform=platform,
          credential_id=data.get('id'),
          token=websafe_encode(authenticator_data.credential_data),
          is_enabled=True,
        )
        status_code, message = 200, _('Complete the registeration.')
    except Exception as err:
      logger.error(str(ex))
      status_code, message = 500, _('Error on server, please try again later.')

    return status_code, message

  @classmethod
  def authenticate_begin(cls, request):
    if request.user.is_authenticated:
      credentials = cls.get_credentials(request.user)
    else:
      credentials = None
    server = cls.get_server(request)
    data, state = server.authenticate_begin(credentials)
    options = dict(data)
    request.session['fido2_state'] = state

    return options

  @classmethod
  def authenticate_complete(cls, request):
    logger = logging.getLogger(__name__)
    data = json.loads(request.POST.get('passkey'))
    user_pk = _pk_value(websafe_decode(data['response']['userHandle']))
    credential_id = data['id']

    try:
      instance = cls.objects.get(
        user__pk=user_pk,
        credential_id=credential_id,
        is_enabled=True,
      )
      server = instance.get_server(request)
      credentials = [AttestedCredentialData(websafe_decode(instance.token))]
      state = request.session.pop('fido2_state'),
      # Authentication
      server.authenticate_complete(state, credentials=credentials, response=data)
      # Update current instance data
      instance.last_used = timezone.now()
      instance.save()
    except (cls.DoesNotExist, ValueError):
      instance = None
    except Exception as ex:
      logger.error(str(ex))
      instance = None

    return instance