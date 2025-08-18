from django import forms
from django.contrib.auth import authenticate
from django.contrib.auth.forms import AuthenticationForm
from django.utils.translation import gettext_lazy as _
from django.views.decorators.debug import sensitive_variables
from .models import Passkey

class BasePasskeyAuthenticationForm(AuthenticationForm):
  passkey = forms.CharField(
    label=_('Passkey'),
    required=False,
    widget=forms.HiddenInput(attrs={'id': 'passkey'}),
  )

  def __init__(self, *args, **kwargs):
    super().__init__(*args, **kwargs)
    self.fields['username'].widget.attrs['autocomplete'] = 'username webauthn'
    self.fields['username'].required = False
    self.fields['password'].required = False

  @sensitive_variables()
  def clean(self):
    username = self.cleaned_data.get('username', '')
    password = self.cleaned_data.get('password', '')
    self.user_cache = authenticate(self.request, username=username, password=password)
    # Check authenticated result
    if self.user_cache is None:
      raise self.get_invalid_login_error()
    else:
      self.confirm_login_allowed(self.user_cache)

    return self.cleaned_data

class PasskeyAuthenticationForm(BasePasskeyAuthenticationForm):
  def __init__(self, *args, **kwargs):
    super().__init__(*args, **kwargs)

    for field in self.fields.values():
      classes = field.widget.attrs.get('class', '')
      field.widget.attrs['class'] = f'{classes} form-control'

class PasskeyStatusUpdateForm(forms.ModelForm):
  class Meta:
    model = Passkey
    fields = []

  def save(self, commit=True):
    instance = super().save(commit=False)
    instance.toggle_passkey_status()

    if commit:
      instance.save()

    return instance