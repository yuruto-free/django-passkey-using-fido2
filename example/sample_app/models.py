import uuid

from django.db import models
from django.contrib.auth.base_user import AbstractBaseUser, BaseUserManager
from django.contrib.auth.hashers import make_password
from django.contrib.auth.models import PermissionsMixin
from django.utils.translation import gettext_lazy as _

class CustomUserManager(BaseUserManager):
  use_in_migrations = True

  def _create_user(self, email, password, **extra_fields):
    if not email:
      raise ValueError(_('The given email must be set.'))
    email = self.normalize_email(email)
    user = self.model(email=email, **extra_fields)
    user.password = make_password(password)
    user.save(using=self._db)

    return user

  def create_user(self, email, password=None, **extra_fields):
    extra_fields.setdefault('is_staff', False)
    extra_fields.setdefault('is_superuser', False)

    return self._create_user(email, password, **extra_fields)

  def create_superuser(self, email, password=None, **extra_fields):
    extra_fields.setdefault('is_staff', True)
    extra_fields.setdefault('is_superuser', True)

    if extra_fields.get('is_staff') is not True:
        raise ValueError(_('Superuser must have is_staff=True.'))
    if extra_fields.get('is_superuser') is not True:
        raise ValueError(_('Superuser must have is_superuser=True.'))

    return self._create_user(email, password, **extra_fields)

class CustomUser(AbstractBaseUser, PermissionsMixin):
  id = models.UUIDField(
    primary_key=True,
    default=uuid.uuid4,
    editable=False,
  )
  email = models.EmailField(
    _('email address'),
    max_length=128,
    unique=True,
    help_text=_('Required. 128 characters allowing only Unicode characters, in addition to @, ., -, and _.'),
  )
  password = models.CharField(
    _('password'),
    max_length=128,
  )
  nick_name = models.CharField(
    _('nick name'),
    max_length=128,
    blank=True,
    help_text=_('Optional. 128 characters or fewer.'),
  )
  is_staff = models.BooleanField(
    _('staff status'),
    default=False,
  )
  is_superuser = models.BooleanField(
    _('superuser status'),
    default=False,
  )
  is_active = models.BooleanField(
    _('active'),
    default=True,
  )
  date_joined = models.DateTimeField(
    _('date joined'),
    auto_now_add=True,
  )

  objects = CustomUserManager()

  EMAIL_FIELD = 'email'
  USERNAME_FIELD = 'email'
  REQUIRED_FIELDS = []

  def __str__(self):
    return self.nick_name or self.email