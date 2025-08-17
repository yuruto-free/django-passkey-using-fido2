from django.contrib import admin
from .models import Passkey

@admin.register(Passkey)
class PasskeyAdmin(admin.ModelAdmin):
  model = Passkey
  fields = ('name', 'platform', 'last_used', 'is_enabled')
  list_display = ('name', 'platform', 'is_enabled')
  list_filter = ('name', 'platform', 'is_enabled')
  search_fields = ('name', 'platform', 'is_enabled')