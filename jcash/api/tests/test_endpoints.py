from datetime import datetime
from unittest import mock

import pytest
from django.test import TestCase

from rest_framework.test import RequestsClient
from django.contrib.auth.models import User
from allauth.account.models import EmailAddress
from allauth.account.utils import setup_user_email

from jcash.api import models


def teardown_module(module):
    pass


class ApiClient(RequestsClient):

    def __init__(self, *args, base_url='', **kwargs):
        super().__init__(*args, **kwargs)
        self.base_url = base_url

    def request(self, method, url, *args, **kwargs):
        resp = super().request(method, self.base_url + url, *args, **kwargs)
        print('RESPONSE', resp.content)
        return resp

    def authenticate(self, username, password):
        resp = self.post('/auth/login/',
                         {'email': username, 'password': password, 'captcha': '123'})
        token = resp.json()['key']
        self.headers = {'Authorization': 'Token ' + token}



@pytest.fixture
def client(live_server):
    return ApiClient(base_url=live_server.url)
