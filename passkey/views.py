from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from django.contrib.auth.views import LoginView, LogoutView
from django.http import JsonResponse
from django.urls import reverse_lazy, reverse
from django.views.generic import (
  View,
  ListView,
  UpdateView,
  DeleteView,
)
from .models import Passkey
from .forms import PasskeyStatusUpdateForm, PasskeyAuthenticationForm

class PasskeyListView(LoginRequiredMixin, ListView):
  model = Passkey
  template_name = 'passkey/passkey_list.html'
  paginate_by = 50
  context_object_name = 'passkeys'

  def get_queryset(self):
    return self.request.user.passkeys.all().order_by('-date_joined')

class PasskeyStatusUpdateView(LoginRequiredMixin, UserPassesTestMixin, UpdateView):
  raise_exception = True
  http_method_names = ['post']
  model = Passkey
  form_class = PasskeyStatusUpdateForm
  success_url = reverse_lazy('passkey:passkey_list')

  def test_func(self):
    instance = self.get_object()
    is_valid = instance.has_update_permission(self.request.user)

    return is_valid

class PasskeyDeleteView(LoginRequiredMixin, UserPassesTestMixin, DeleteView):
  raise_exception = True
  http_method_names = ['post']
  model = Passkey
  success_url = reverse_lazy('passkey:passkey_list')

  def test_func(self):
    instance = self.get_object()
    is_valid = instance.has_delete_permission(self.request.user)

    return is_valid

class RegisterPasskey(LoginRequiredMixin, View):
  raise_exception = True
  http_method_names = ['get', 'post']

  def get(self, request, *args, **kwargs):
    options = Passkey.register_begin(request)
    response = JsonResponse(options, json_dumps_params={'ensure_ascii': False})

    return response

  def post(self, request, *args, **kwargs):
    status_code, message = Passkey.register_complete(request)
    response = JsonResponse({'message': message}, json_dumps_params={'ensure_ascii': False}, status=status_code)

    return response

class BeginPasskeyAuthentication(View):
  raise_exception = True
  http_method_names = ['get']

  def get(self, request, *args, **kwargs):
    options = Passkey.authenticate_begin(request)
    response = JsonResponse(options, json_dumps_params={'ensure_ascii': False})

    return response

class PasskeyLoginView(LoginView):
  redirect_authenticated_user = True
  form_class = PasskeyAuthenticationForm
  template_name = 'passkey/login.html'

class PasskeyLogoutView(LogoutView):
  pass