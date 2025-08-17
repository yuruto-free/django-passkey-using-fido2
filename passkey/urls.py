from django.urls import path
from . import views

app_name = 'passkey'

urlpatterns = [
  path('passkey-list', views.PasskeyListView.as_view(), name='passkey_list'),
  path('update-passkey/<pk>', views.PasskeyStatusUpdateView.as_view(), name='update_passkey_status'),
  path('delete-passkey/<pk>', views.PasskeyDeleteView.as_view(), name='delete_passkey'),
  path('register-passkey', views.RegisterPasskey.as_view(), name='register_passkey'),
  path('begin-passkey-authentication', views.BeginPasskeyAuthentication.as_view(), name='begin_passkey_authentication'),
  path('login', views.PasskeyLoginView.as_view(), name='login'),
  path('logout', views.PasskeyLogoutView.as_view(), name='logout'),
]