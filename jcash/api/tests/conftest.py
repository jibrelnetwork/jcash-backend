from datetime import datetime

import pytest

from django.contrib.auth.models import User
from allauth.account.models import EmailAddress

from jcash.api import models


@pytest.fixture
def users():
    users = [
        User.objects.create_user('user1@mail.local', 'user1@mail.local', 'password1'),
        User.objects.create_user('user2@mail.local', 'user2@mail.local', 'password2'),
        User.objects.create_user('user3@mail.local', 'user3@mail.local', 'password3'),
        User.objects.create_user('user4@mail.local', 'user4@mail.local', 'password4'),
        User.objects.create_user('user5@mail.local', 'user5@mail.local', 'password5'),
        User.objects.create_user('user6@mail.local', 'user6@mail.local', 'password6'),
        User.objects.create_user('user7@mail.local', 'user7@mail.local', 'password7'),
    ]
    for user in users:
        EmailAddress.objects.create(user=user,
                                    email=user.username,
                                    primary=True,
                                    verified=False)
    return users


@pytest.fixture
def accounts(users):
    _accounts = []
    for user in users:
        _accounts.append(models.Account.objects.create(user=user))
    return _accounts
