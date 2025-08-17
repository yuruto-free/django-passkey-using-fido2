from django.contrib.auth.backends import ModelBackend
from django.utils.translation import gettext_lazy as _
from .models import Passkey

class PasskeyModelBackend(ModelBackend):
  def update_passkey_session(self, request, instance=None):
    if instance is None:
      request.session['passkey'] = {
        'use_passkey': False,
        'name': None,
        'id': None,
        'platform': None,
        'cross_platform': None,
      }
      user = None
    else:
      request.session['passkey'] = {
        'use_passkey': True,
        'name': instance.name,
        'id': str(instance.pk),
        'platform': instance.platform,
        'cross_platform': instance.get_platform(request) == instance.platform,
      }
      user = instance.user

    return user

  def authenticate(self, request, username='', password='', **kwargs):
    if request is None:
      raise Exception(_('`request` is required for passkey.backends.PasskeyModelBackend.'))

    if username and password:
      self.update_passkey_session(request)
      user = super().authenticate(request, username=username, password=password, **kwargs)
    else:
      passkey = request.POST.get('passkey')

      if passkey is None:
        raise Exception(_('`passkey` is required in request.POST.'))
      elif passkey != '':
        instance = Passkey.authenticate_complete(request)
        user = self.update_passkey_session(request, instance)
      else:
        user = None

    return user