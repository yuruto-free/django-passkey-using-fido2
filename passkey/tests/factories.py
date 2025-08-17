import factory
from factory.fuzzy import FuzzyChoice
from django.contrib.auth.models import User
from faker import Factory as FakerFactory
from passkey.models import Passkey

faker = FakerFactory.create()

class UserFactory(factory.django.DjangoModelFactory):
  class Meta:
    model = User

  email = factory.Sequence(lambda idx: f'user{idx}@example.com')
  username = factory.Sequence(lambda idx: f'user{idx}')
  password = factory.LazyAttribute(lambda instance: faker.pystr(min_chars=12, max_chars=128))
  is_active = True
  is_staff = False
  is_superuser = False

class PasskeyFactory(factory.django.DjangoModelFactory):
  class Meta:
    model = Passkey

  class Params:
    platform_types = ['Apple', 'Amazon', 'Microsoft', 'Google', 'Unknown']

  user = factory.SubFactory(UserFactory)
  name = factory.LazyAttribute(lambda instance: faker.pystr(min_chars=1, max_chars=255))
  platform = FuzzyChoice(Params.platform_types)
  credential_id = factory.Sequence(lambda idx: '{}{}'.format(faker.pystr(min_chars=1, max_chars=192), idx))
  token = factory.LazyAttribute(lambda instance: faker.pystr(min_chars=255, max_chars=255))
  is_enabled = True