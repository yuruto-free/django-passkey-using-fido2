from django.contrib import admin
from .models import CustomUser

@admin.register(CustomUser)
class UserAdmin(admin.ModelAdmin):
  model = CustomUser
  fields = ('email', 'nick_name', 'is_active', 'is_staff', 'is_superuser')
  list_display = ('email', 'nick_name', 'is_active', 'is_staff', 'is_superuser')
  list_filter = ('email', 'nick_name', 'is_active')
  search_fields = ('email', 'nick_name', 'is_active')