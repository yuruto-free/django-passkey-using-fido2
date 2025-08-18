import pytest
from django.core.exceptions import ValidationError
from . import factories
from passkey import models, forms

@pytest.mark.form
@pytest.mark.django_db
class TestBasePasskeyAuthenticationForm:
  def test_init_method(self):
    form = forms.BasePasskeyAuthenticationForm()

    assert form.fields['username'].widget.attrs['autocomplete'] == 'username webauthn'
    assert not form.fields['username'].required
    assert not form.fields['password'].required

  def test_validation(self, mocker, get_users):
    _, user = get_users
    mocker.patch('passkey.forms.authenticate', return_value=user)
    params = {
      'username': '',
      'password': '',
    }
    form = forms.BasePasskeyAuthenticationForm(data=params)
    is_valid = form.is_valid()

    assert is_valid

  def test_clean_method_with_invalid_authentication(self, mocker):
    mocker.patch('passkey.forms.authenticate', return_value=None)
    form = forms.BasePasskeyAuthenticationForm()
    form.cleaned_data = {}
    err_msg = 'Please enter a correct %(username)s and password. Note that both fields may be case-sensitive.'

    with pytest.raises(ValidationError) as ex:
      form.clean()

    assert err_msg == ex.value.args[0]

  def test_clean_method_without_invalid_user(self, mocker):
    user = factories.UserFactory(is_active=False)
    mocker.patch('passkey.forms.authenticate', return_value=user)
    form = forms.BasePasskeyAuthenticationForm()
    form.cleaned_data = {}
    err_msg = 'This account is inactive.'

    with pytest.raises(ValidationError) as ex:
      form.clean()

    assert err_msg == ex.value.args[0]

@pytest.mark.form
@pytest.mark.django_db
class TestPasskeyStatusUpdateForm:
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
  def test_update_enable_state(self, get_users, is_enabled, expected):
    _, user = get_users
    form = forms.PasskeyStatusUpdateForm(data={})
    form.instance = factories.PasskeyFactory(user=user, is_enabled=is_enabled)
    is_valid = form.is_valid()
    target = form.save()
    updated = models.Passkey.objects.get(pk=target.pk)

    assert is_valid
    assert updated.is_enabled == expected

  def test_no_commit(self, get_users):
    _, user = get_users
    old_obj = factories.PasskeyFactory(user=user, is_enabled=True)
    form = forms.PasskeyStatusUpdateForm(data={})
    form.instance = old_obj
    is_valid = form.is_valid()
    target = form.save(commit=False)
    updated = models.Passkey.objects.get(pk=target.pk)

    assert is_valid
    assert updated.is_enabled != old_obj.is_enabled