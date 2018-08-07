from datetime import datetime
from unittest import mock
import json

import pytest
from django.test import TestCase
from rest_framework.test import RequestsClient
from rest_framework.authtoken.models import Token
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
        self.token = resp.json()['key']
        self.headers = {'Authorization': 'Token ' + self.token}
        self.user_id = Token.objects.get(key=self.token).user.pk


@pytest.fixture
def client(live_server):
    return ApiClient(base_url=live_server.url)


def test_success_login_lowercase(live_server, users):
    client = ApiClient(base_url=live_server.url)
    resp = client.post('/auth/login/',
                       {'email': 'user1@mail.local',
                        'password': 'password1',
                        'captcha': '123'})
    assert resp.status_code == 200
    assert resp.json()['success'] == True


def test_success_login_uppercase(live_server, users):
    client = ApiClient(base_url=live_server)
    resp = client.post('/auth/login/',
                       {'email': 'USER1@MAIL.LOCAL',
                        'password': 'password1',
                        'captcha': '123'})
    assert resp.status_code == 200
    assert resp.json()['success'] == True


def test_fail_login_captcha(live_server, users):
    client = ApiClient(base_url=live_server.url)
    resp = client.post('/auth/login/',
                       {'email': 'user1@mail.local',
                        'password': 'password1'})
    assert resp.status_code != 200
    assert resp.json()['success'] == False
    assert 'captcha' in resp.json()['errors']


def test_success_logout_with_auth(live_server, users):
    client = ApiClient(base_url=live_server.url)
    client.authenticate('user1@mail.local', 'password1')
    resp = client.post('/auth/logout/')
    assert resp.status_code == 200
    assert resp.json()['success'] == True


def test_success_logout_wo_auth(live_server, users):
    client = ApiClient(base_url=live_server.url)
    resp = client.post('/auth/logout/')
    assert resp.status_code == 200
    assert resp.json()['success'] == True


def test_get_django_user_info(client, users):
    username = 'user1@mail.local'
    client.authenticate(username, 'password1')
    resp = client.get('/auth/user/')
    assert resp.status_code == 200
    assert resp.json()['success'] == True
    assert resp.json()['username'] == username
    assert resp.json()['email'] == username


def test_fail_update_user_info(client, users):
    client.authenticate('user1@mail.local', 'password1')
    resp = client.post('/auth/user/', {"username": 'user_1@mail.local'})
    assert resp.status_code != 200
    assert resp.json()['success'] == False


def test_success_password_reset_and_confirm_and_isalive(client, users, accounts):
    email = 'user1@mail.local'
    client.authenticate(email, 'password1')

    #check /auth/passord/reset/ endpoint
    resp = client.post('/auth/password/reset/',
                       {'email': email, 'captcha': '123'})
    assert resp.status_code == 200
    assert resp.json() == {'success': True}
    notifications = models.Notification.objects.filter(email=email,
                                                       type=models.NotificationType.password_reset)
    assert notifications.count() == 1
    activate_url = notifications[0].meta['activate_url']
    frontend_password_reset_confirm_query = '/auth/recovery/confirm/'
    uid_token = activate_url.split(frontend_password_reset_confirm_query)[1]
    uid = uid_token.split('/')[0]
    token = uid_token.split('/')[1]

    #check /auth/isalive/ enpoint
    resp = client.post('/auth/isalive/', json.dumps({'uid': uid, 'token': token}), headers={'content-type': 'application/json'})
    assert resp.status_code == 200
    assert resp.json()['success'] == True

    #check /auth/password/reset/confirm endpoint
    resp = client.post('/auth/password/reset/confirm/',
                       {'new_password': '12Qwerty@', 'uid': uid, 'token': token})
    assert resp.status_code == 200
    assert resp.json() == {'success': True}

    #check /auth/passord/reset/ endpoint (uppercase email)
    resp = client.post('/auth/password/reset/',
                       {'email': 'USER1@MAIL.LOCAL', 'captcha': '123'})
    assert resp.status_code == 200
    assert resp.json() == {'success': True}


def test_fail_password_reset_wo_captcha(users, live_server):
    client = ApiClient(base_url=live_server.url)
    resp = client.post('/auth/password/reset/',
                       {'email': 'user1@mail.local'})
    assert resp.status_code != 200
    assert resp.json()['success'] == False
    assert 'captcha' in resp.json()['errors']


def test_fail_password_reset_wo_email(users, live_server):
    client = ApiClient(base_url=live_server.url)
    resp = client.post('/auth/password/reset/',
                       {'captcha': '123'})
    assert resp.status_code != 200
    assert resp.json()['success'] == False
    assert 'email' in resp.json()['errors']


def test_fail_password_reset_confirm_wo_password(users, live_server):
    client = ApiClient(base_url=live_server.url)
    resp = client.post('/auth/password/reset/confirm/',
                       {'uid': 'AB', 'token': '123-123456789'})
    assert resp.status_code != 200
    assert resp.json()['success'] == False
    assert 'new_password' in resp.json()['errors']


def test_fail_password_reset_confirm_wo_uid(users, live_server):
    client = ApiClient(base_url=live_server.url)
    resp = client.post('/auth/password/reset/confirm/',
                       {'new_password': '12Qwerty@', 'token': '123-123456789'})
    assert resp.status_code != 200
    assert resp.json()['success'] == False
    assert 'uid' in resp.json()['errors']


def test_fail_password_reset_confirm_wo_token(users, live_server):
    client = ApiClient(base_url=live_server.url)
    resp = client.post('/auth/password/reset/confirm/',
                       {'new_password': '12Qwerty@', 'uid': 'AB'})
    assert resp.status_code != 200
    assert resp.json()['success'] == False
    assert 'token' in resp.json()['errors']


def test_fail_password_reset_confirm_wrong_uid(users, live_server):
    client = ApiClient(base_url=live_server.url)
    resp = client.post('/auth/password/reset/confirm/',
                       {'new_password': '12Qwerty@', 'uid': 'AB', 'token': '123-123456789'})
    assert resp.status_code != 200
    assert resp.json()['success'] == False
    assert 'uid' in resp.json()['errors']


def test_fail_isalive_wo_uid(users, live_server):
    client = ApiClient(base_url=live_server.url)
    resp = client.post('/auth/isalive/', json.dumps({'token': '123-123456789'}),
                       headers={'content-type': 'application/json'})
    assert resp.status_code != 200
    assert resp.json()['success'] == False


def test_fail_isalive_wo_token(users, live_server):
    client = ApiClient(base_url=live_server.url)
    resp = client.post('/auth/isalive/', json.dumps({'uid': 'AB'}),
                       headers={'content-type': 'application/json'})
    assert resp.status_code != 200
    assert resp.json()['success'] == False


def test_success_validate_password(users, live_server):
    client = ApiClient(base_url=live_server.url)
    resp = client.post('/auth/validate-password/', json.dumps({'password': 'AbcDe@3_z'}),
                       headers={'content-type': 'application/json'})
    assert resp.status_code == 200
    assert resp.json()['success'] == True


def test_fail_validate_password(users, live_server):
    client = ApiClient(base_url=live_server.url)
    resp = client.post('/auth/validate-password/', json.dumps({'password': 'bcDe3z1'}),
                       headers={'content-type': 'application/json'})
    assert resp.status_code != 200
    assert resp.json()['success'] == False
    assert 'password' in resp.json()['errors']


def test_success_password_change(client, users):
    client.authenticate('user1@mail.local', 'password1')
    resp = client.post('/auth/password/change/', json.dumps({'old_password': 'password1', 'new_password': 'bcDe3z1@_'}),
                       headers={'content-type': 'application/json'})
    assert resp.status_code == 200
    assert resp.json()['success'] == True


def test_fail_password_change_wo_auth(users, live_server):
    client = ApiClient(base_url=live_server)
    resp = client.post('/auth/password/change/', json.dumps({'old_password': 'password1', 'new_password': 'bcDe3z1@_'}),
                       headers={'content-type': 'application/json'})
    assert resp.status_code != 200
    assert resp.json()['success'] == False
    assert 'error' in resp.json()


def test_fail_password_change_wo_old_password(client, users):
    client.authenticate('user1@mail.local', 'password1')
    resp = client.post('/auth/password/change/', json.dumps({'new_password': 'bcDe3z1@_'}),
                       headers={'content-type': 'application/json'})
    assert resp.status_code != 200
    assert resp.json()['success'] == False
    assert 'old_password' in resp.json()['errors']


def test_fail_password_change_wo_new_password(client, users):
    client.authenticate('user1@mail.local', 'password1')
    resp = client.post('/auth/password/change/', json.dumps({'old_password': 'password1'}),
                       headers={'content-type': 'application/json'})
    assert resp.status_code != 200
    assert resp.json()['success'] == False
    assert 'new_password' in resp.json()['errors']


def test_success_registration_and_registration_verify(live_server):
    client = ApiClient(base_url=live_server)
    user_data = {
        'email': 'aa@aa.aa',
        'password': '123qwerty@',
        'captcha': 'zxc',
        'tracking': {'ga_id': '123.456.7890', 'utm_campaign': 'Cmp1', 'utm_source': 'src'},
    }
    resp = client.post('/auth/registration/', json=user_data)
    assert resp.status_code == 201
    account = models.Account.objects.get(user__username=user_data['email'])
    assert account.tracking == user_data['tracking']
    assert 'key' in resp.json()

    assert EmailAddress.objects.get(email=user_data['email']).verified is False

    nots = models.Notification.objects.filter(email=user_data['email'],
                                              type=models.NotificationType.verify_email).all()
    assert len(nots) == 1

    data = {'key': nots[0].meta['activate_url'].split('/')[-1]}
    resp = client.post(
        '/auth/registration/verify-email/', json=data)

    assert resp.status_code == 200
    assert EmailAddress.objects.get(email=user_data['email']).verified is True


def test_success_registration_emplty_tracking(client, addresses):
    user_data = {
        'email': 'aa@aa.aa',
        'password': '123qwerty#',
        'captcha': 'zxc',
    }
    resp = client.post('/auth/registration/', json=user_data)
    assert resp.status_code == 201
    account = models.Account.objects.get(user__username=user_data['email'])
    assert account.tracking == {}


def test_success_registration_email_uppercase(client, addresses):
    user_data = {
        'email': 'AAA@AA.AA',
        'password': '123qwerty#',
        'captcha': 'zxc',
    }
    resp = client.post('/auth/registration/', json=user_data)
    assert resp.status_code == 201
    assert resp.json()['success'] == True


def test_fail_registration_duplicate_email(client, addresses):
    user_data = {
        'email': 'user1@mail.local',
        'password': '123qwerty#',
        'captcha': 'zxc',
    }
    resp = client.post('/auth/registration/', json=user_data)
    assert resp.status_code != 200
    assert resp.json()['success'] == False
