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


def test_transactions_empty(client, users):
    client.authenticate('user1@main.com', 'password1')
    resp = client.get('/api/transactions/')
    assert resp.status_code == 200
    assert resp.json() == []


def test_transactions(client, users, addresses, transactions, jnt):
    models.Withdraw.objects.create(
        transaction_id='3000',
        value=30000,
        mined=datetime(2017, 11, 15),
        created=datetime(2017, 11, 15),
        block_height=200,
        status='success',
        user=users[0],
    )
    client.authenticate('user1@main.com', 'password1')
    resp = client.get('/api/transactions/')
    assert resp.status_code == 200
    assert len(resp.json()) == 4
    assert resp.json() == [
        {'jnt': 30000,
         'type': 'outgoing',
         'date': '00:00 11/15/2017',
         'TXtype': 'ETH',
         'TXhash': '3000',
         'status': 'success',
         'amount_usd': None,
         'amount_cryptocurrency': None},
        {'jnt': 10,
         'type': 'incoming',
         'date': '00:00 11/14/2017',
         'TXtype': 'ETH',
         'TXhash': '1000',
         'status': 'success',
         'amount_usd': 1,
         'amount_cryptocurrency': 0.5},
        {'jnt': 30,
         'type': 'incoming',
         'date': '00:00 11/13/2017',
         'TXtype': 'ETH',
         'TXhash': '1500',
         'status': 'pending',
         'amount_usd': 3,
         'amount_cryptocurrency': 0.5},
        {'jnt': 20,
         'type': 'incoming',
         'date': '12:00 11/12/2017',
         'TXtype': 'BTC',
         'TXhash': '2000',
         'status': 'success',
         'amount_usd': 2,
         'amount_cryptocurrency': 2.5},
    ]


def test_transactions_anon(client):
    resp = client.get('/api/transactions/')
    assert resp.status_code == 401


def test_get_account_empty(client, users):
    client.authenticate('user1@main.com', 'password1')
    resp = client.get('/api/account/')
    assert resp.status_code == 200
    assert resp.json() == {'date_of_birth': None,
                           'username': 'user1@main.com',
                           'first_name': '',
                           'last_name': '',
                           'terms_confirmed': False,
                           'document_url': '',
                           'document_type': '',
                           'identity_verification_status': None,
                           'verification_form_status': None,
                           'is_document_skipped': False,
                           'citizenship': '',
                           'residency': '',
                           'is_email_confirmed': False,
                           'btc_address': None,
                           'eth_address': None,
                           'jnt_balance': 0}


def test_account_verification_statuses(client, accounts):
    accounts[1].is_document_skipped = True
    accounts[2].is_identity_verified = True
    accounts[3].is_identity_verification_declined = True
    accounts[4].document_url = 'aaa'

    accounts[1].save()
    accounts[2].save()
    accounts[3].save()
    accounts[4].save()

    client.authenticate('user1@main.com', 'password1')
    resp = client.get('/api/account/')
    assert resp.json()['identity_verification_status'] is None

    client.authenticate('user2@main.com', 'password2')
    resp = client.get('/api/account/')
    assert resp.json()['identity_verification_status'] == 'Pending'

    client.authenticate('user3@main.com', 'password3')
    resp = client.get('/api/account/')
    assert resp.json()['identity_verification_status'] == 'Approved'

    client.authenticate('user4@main.com', 'password4')
    resp = client.get('/api/account/')
    assert resp.json()['identity_verification_status'] == 'Declined'

    client.authenticate('user5@main.com', 'password5')
    resp = client.get('/api/account/')
    assert resp.json()['identity_verification_status'] == 'Preliminarily Approved'


def test_update_account(client, users, transactions):
    models.Jnt.objects.create(
        jnt_value=1.5,
        currency_to_usd_rate=1.0,
        usd_value=1.0,
        jnt_to_usd_rate=1.0,
        active=True,
        created=datetime.now(),
        transaction=transactions[0])
    client.authenticate('user1@main.com', 'password1')
    resp = client.put('/api/account/', {'first_name': 'John', 'terms_confirmed': True})
    assert resp.status_code == 200
    assert resp.json() == {'date_of_birth': None,
                           'username': 'user1@main.com',
                           'first_name': 'John',
                           'last_name': '',
                           'terms_confirmed': True,
                           'document_url': '',
                           'document_type': '',
                           'identity_verification_status': None,
                           'verification_form_status': 'terms_confirmed',
                           'is_document_skipped': False,
                           'citizenship': '',
                           'residency': '',
                           'is_email_confirmed': False,
                           'btc_address': 'aba',
                           'eth_address': 'aaa',
                           'jnt_balance': 1.5}

    resp = client.put('/api/account/',
                      {'first_name': 'John',
                       'last_name': 'Smith',
                       'citizenship': 'UK',
                       'residency': 'UK',
                       'date_of_birth': '1999-12-22',
                       })
    assert resp.status_code == 200
    assert resp.json()['verification_form_status'] == 'personal_data_filled'

    resp = client.put('/api/account/', {'is_document_skipped': True})
    assert resp.status_code == 200
    assert resp.json()['verification_form_status'] == 'passport_skipped'

    resp = client.put('/api/account/', {'document_url': 'http://qwe.rt'})
    assert resp.status_code == 200
    assert resp.json()['verification_form_status'] == 'passport_uploaded'


def test_get_raised_tokens_empty(client, users, settings):
    resp = client.get('/api/raised-tokens/')
    assert resp.status_code == 200
    assert resp.json() == {'raised_tokens': settings.RAISED_TOKENS_SHIFT + 0}


def test_get_raised_tokens(client, users, transactions, settings):
    models.Jnt.objects.create(
        jnt_value=1.5,
        currency_to_usd_rate=1.0,
        usd_value=1.0,
        jnt_to_usd_rate=1.0,
        active=True,
        created=datetime.now(),
        transaction=transactions[0],
        is_sale_allocation=False)
    models.Jnt.objects.create(
        jnt_value=0.75,
        currency_to_usd_rate=1.0,
        usd_value=1.0,
        jnt_to_usd_rate=1.0,
        active=True,
        created=datetime.now(),
        transaction=transactions[1])

    models.PresaleJnt.objects.create(
        jnt_value=10.00,
        created=datetime.now(),
        user=users[0],
        is_presale_round=True,
        is_sale_allocation=True,
    )

    models.PresaleJnt.objects.create(
        jnt_value=30.00,
        created=datetime.now(),
        user=users[1],
        is_presale_round=False,
        is_sale_allocation=True,
    )

    models.PresaleJnt.objects.create(
        jnt_value=60.00,
        created=datetime.now(),
        user=users[1],
        is_presale_round=False,
        is_sale_allocation=False,
    )

    resp = client.get('/api/raised-tokens/')
    assert resp.status_code == 200
    assert resp.json() == {'raised_tokens': settings.RAISED_TOKENS_SHIFT + 0.75 + 30}


def test_get_withdraw_address_empty(client, users):
    client.authenticate('user1@main.com', 'password1')
    resp = client.get('/api/withdraw-address/')
    assert resp.status_code == 200
    assert resp.json() == {'address': None}


def test_get_withdraw_address(client, users):
    models.Account.objects.create(withdraw_address='aaaxxx', user=users[0])
    client.authenticate('user1@main.com', 'password1')
    resp = client.get('/api/withdraw-address/')
    assert resp.status_code == 200
    assert resp.json() == {'address': 'aaaxxx'}


def test_put_withdraw_address_empty(client, users):
    EmailAddress.objects.filter(email='user1@main.com').update(verified=True)

    client.authenticate('user1@main.com', 'password1')
    resp = client.get('/api/withdraw-address/')
    assert resp.status_code == 200
    assert resp.json() == {'address': None}
    resp = client.put('/api/withdraw-address/', {})
    assert resp.status_code == 400
    resp = client.put('/api/withdraw-address/', {'address': None})
    assert resp.status_code == 400


def test_put_withdraw_address_email_not_confirmed(client, users):
    client.authenticate('user1@main.com', 'password1')
    resp = client.get('/api/withdraw-address/')
    assert resp.status_code == 200
    assert resp.json() == {'address': None}
    resp = client.put('/api/withdraw-address/',
                      {'address': '0x3BA2E2565dB2c018aDd0b24483fE99fC2cCCDa8e'})
    assert resp.status_code == 403
    assert resp.json() == {'detail': 'Please confirm the e-mail before submitting the Ethereum address'}


def test_put_withdraw_address_validate(client, users):
    EmailAddress.objects.filter(email='user1@main.com').update(verified=True)

    client.authenticate('user1@main.com', 'password1')
    resp = client.get('/api/withdraw-address/')
    assert resp.status_code == 200
    assert resp.json() == {'address': None}
    resp = client.put('/api/withdraw-address/', {'address': ''})
    assert resp.status_code == 400
    resp = client.put('/api/withdraw-address/', {'address': '1HEVUxtxGjGnuRT5NsamD6V4RdUduRHqFv'})
    assert resp.status_code == 400
    resp = client.put('/api/withdraw-address/', {'address': '3BA2E2565dB2c018aDd0b24483fE99fC2cCCDa8e'})
    assert resp.status_code == 400
    resp = client.put('/api/withdraw-address/', {'address': '0x3BA2E2565dB2c018aDd0b24483fE99fC2cCCDa8'})
    assert resp.status_code == 400
    resp = client.put('/api/withdraw-address/', {'address': '0x3dA2E2565dB2c018aDd0b24483fE99fC2cCCDa8e'})
    assert resp.status_code == 400
    resp = client.put('/api/withdraw-address/', {'address': '0x3BA2E2565dB2c018aDd0b24483fE99fC2cCCDa8e'})
    assert resp.status_code == 200
    assert resp.json() == {'address': '0x3BA2E2565dB2c018aDd0b24483fE99fC2cCCDa8e'}
    resp = client.put('/api/withdraw-address/', {'address': '0xde709f2102306220921060314715629080e2fb77'})
    assert resp.status_code == 200
    assert resp.json() == {'address': '0xde709f2102306220921060314715629080e2fb77'}


def test_withdraw_jnt(client, users, addresses, jnt, settings):
    settings.WITHDRAW_AVAILABLE_SINCE = datetime.now()
    EmailAddress.objects.filter(email='user1@main.com').update(verified=True)

    client.authenticate('user1@main.com', 'password1')
    account = models.Account.objects.create(withdraw_address='aaaxxx', user=users[0], is_identity_verified=True)
    assert account.get_jnt_balance() == 30
    resp = client.post('/api/withdraw-jnt/')
    assert resp.status_code == 200
    assert resp.json() == {'detail': 'JNT withdrawal is requested. Check you email for confirmation.'}

    op = models.Operation.objects.first()
    withdrawals = models.Withdraw.objects.all()

    assert op.operation == models.Operation.OP_WITHDRAW_JNT
    assert op.params == {'address': 'aaaxxx',
                         'jnt_amount': withdrawals[0].value,
                         'withdraw_id': withdrawals[0].pk}
    assert op.user == users[0]

    assert len(withdrawals) == 1
    assert withdrawals[0].user == users[0]
    assert withdrawals[0].value == 30
    assert withdrawals[0].to == account.withdraw_address
    assert withdrawals[0].status == models.TransactionStatus.not_confirmed
    assert account.get_jnt_balance() == 0

    nots = models.Notification.objects.filter(email=users[0].username).all()
    assert len(nots) == 1
    assert nots[0].type == models.NotificationType.withdrawal_request
    url = nots[0].meta['confirm_url']
    op_id = url.split('/')[-2]
    token = url.split('/')[-1]
    assert str(op.pk) == op_id
    op.validate_token(token)


def test_withdraw_jnt_no_jnt(client, users, addresses, jnt, settings):
    settings.WITHDRAW_AVAILABLE_SINCE = datetime.now()
    EmailAddress.objects.filter(email='user3@main.com').update(verified=True)
    account = models.Account.objects.create(withdraw_address='aaaxxx', user=users[2], is_identity_verified=True)

    client.authenticate('user3@main.com', 'password3')
    assert account.get_jnt_balance() == 0
    resp = client.post('/api/withdraw-jnt/')
    assert resp.status_code == 400
    assert resp.json() == {'detail': 'Impossible withdrawal. Check you balance.'}


def test_registration(client, addresses):
    user_data = {
        'email': 'aa@aa.aa',
        'password': '123qwerty',
        'password_confirm': '123qwerty',
        'captcha': 'zxc',
        'tracking': {'ga_id': '123.456.7890', 'utm_campaign': 'Cmp1', 'utm_source': 'src'},
    }
    resp = client.post('/auth/registration/', json=user_data)
    assert resp.status_code == 201
    account = models.Account.objects.get(user__username=user_data['email'])
    assert account.tracking == user_data['tracking']
    assert 'key' in resp.json()

    assert EmailAddress.objects.get(email=user_data['email']).verified is False

    nots = models.Notification.objects.filter(email=user_data['email']).all()
    assert len(nots) == 1
    assert nots[0].type == models.NotificationType.account_created

    data = {'key': nots[0].meta['activate_url'].split('/')[-1]}
    resp = client.post(
        '/auth/registration/verify-email/', json=data)

    assert resp.status_code == 200
    assert EmailAddress.objects.get(email=user_data['email']).verified is True
    assert len(account.user.pay_addresses.all()) == 2


def test_registration_emplty_tracking(client, addresses):
    user_data = {
        'email': 'aa@aa.aa',
        'password': '123qwerty',
        'password_confirm': '123qwerty',
        'captcha': 'zxc',
        # 'tracking': {'ga_id': '123.456.7890', 'utm_campaign': 'Cmp1', 'utm_source': 'src'},
    }
    resp = client.post('/auth/registration/', json=user_data)
    assert resp.status_code == 201
    account = models.Account.objects.get(user__username=user_data['email'])
    assert account.tracking == {}


def test_change_withdraw_address_request(client, accounts):
    EmailAddress.objects.filter(email='user1@main.com').update(verified=True)
    client.authenticate('user1@main.com', 'password1')
    data = {'address': '0x3BA2E2565dB2c018aDd0b24483fE99fC2cCCDa8e'}
    resp = client.put('/api/withdraw-address/', data)
    assert resp.status_code == 200
    op = models.Operation.objects.first()
    assert op.operation == models.Operation.OP_CHANGE_ADDRESS
    assert op.params == data
    assert op.user == accounts[0].user
    assert models.Account.objects.get(pk=accounts[0].pk).withdraw_address is None

    nots = models.Notification.objects.filter(email=accounts[0].user.username).all()
    assert len(nots) == 1
    assert nots[0].type == models.NotificationType.withdraw_address_change_request
    url = nots[0].meta['confirm_url']
    op_id = url.split('/')[-2]
    token = url.split('/')[-1]
    assert str(op.pk) == op_id
    op.validate_token(token)


def test_operation_confirm_change_address_ok(client, users, accounts):
    EmailAddress.objects.filter(email='user1@main.com').update(verified=True)
    client.authenticate('user1@main.com', 'password1')
    params = {'address': '0x3BA2E2565dB2c018aDd0b24483fE99fC2cCCDa8e'}
    op = models.Operation.objects.create(
        operation=models.Operation.OP_CHANGE_ADDRESS,
        user=users[0],
        params=params
    )
    data = {
        'operation_id': str(op.pk),
        'token': op.key
    }
    resp = client.post('/api/withdraw-address/confirm/', data)
    accounts[0].refresh_from_db()
    op.refresh_from_db()
    assert resp.status_code == 200
    assert accounts[0].withdraw_address == params['address']
    assert op.confirmed_at is not None

    accounts[0].withdraw_address = '0x123'
    accounts[0].save()
    resp = client.post('/api/withdraw-address/confirm/', data)
    assert resp.status_code == 500
    accounts[0].refresh_from_db()
    assert accounts[0].withdraw_address == '0x123'


def test_operation_confirm_withdraw_jnt_ok(client, users, accounts, settings):
    EmailAddress.objects.filter(email='user1@main.com').update(verified=True)
    settings.WITHDRAW_AVAILABLE_SINCE = datetime.now()
    accounts[0].is_identity_verified = True
    accounts[0].save()

    client.authenticate('user1@main.com', 'password1')
    withdraw = models.Withdraw.objects.create(
        user=users[0],
        value=123,
        to='0x3BA2E2565dB2c018aDd0b24483fE99fC2cCCDa8e',
        created=datetime.now()
    )
    params = {'address': '0x3BA2E2565dB2c018aDd0b24483fE99fC2cCCDa8e',
              'withdraw_id': withdraw.pk,
              'jnt_amount': withdraw.value}
    op = models.Operation.objects.create(
        operation=models.Operation.OP_WITHDRAW_JNT,
        user=users[0],
        params=params
    )
    data = {
        'operation_id': str(op.pk),
        'token': op.key
    }

    assert withdraw.status == models.TransactionStatus.not_confirmed
    resp = client.post('/api/withdraw-jnt/confirm/', data)
    withdraw.refresh_from_db()
    assert resp.status_code == 200
    assert withdraw.status == models.TransactionStatus.confirmed

    resp = client.post('/api/withdraw-address/confirm/', data)
    assert resp.status_code == 500
    withdraw.refresh_from_db()
    assert withdraw.status == models.TransactionStatus.confirmed


def test_operation_confirm_withdraw_jnt_email_not_confirmed(client, users, accounts, settings):
    settings.WITHDRAW_AVAILABLE_SINCE = datetime.now()
    client.authenticate('user1@main.com', 'password1')
    data = {'token': '123', 'operation_id': 'qwe'}
    resp = client.post('/api/withdraw-jnt/confirm/', data)
    assert resp.status_code == 403


def test_operation_confirm_withdraw_jnt_invalid_params(client, users, accounts, settings):
    settings.WITHDRAW_AVAILABLE_SINCE = datetime.now()
    EmailAddress.objects.filter(email='user1@main.com').update(verified=True)
    accounts[0].is_identity_verified = True
    accounts[0].save()
    client.authenticate('user1@main.com', 'password1')
    data = {}
    resp = client.post('/api/withdraw-jnt/confirm/', data)
    assert resp.status_code == 400
    assert resp.json() == {'token': ['This field is required.'],
                           'operation_id': ['This field is required.']}


def test_operation_confirm_change_address_email_not_confirmed(client, users, accounts, settings):
    settings.WITHDRAW_AVAILABLE_SINCE = datetime.now()
    client.authenticate('user1@main.com', 'password1')
    data = {'token': '123', 'operation_id': 'qwe'}
    resp = client.post('/api/withdraw-address/confirm/', data)
    assert resp.status_code == 403


def test_operation_confirm_change_address_invalid_params(client, users, accounts, settings):
    settings.WITHDRAW_AVAILABLE_SINCE = datetime.now()
    EmailAddress.objects.filter(email='user1@main.com').update(verified=True)
    client.authenticate('user1@main.com', 'password1')
    data = {}
    resp = client.post('/api/withdraw-address/confirm/', data)
    assert resp.status_code == 400
    assert resp.json() == {'token': ['This field is required.'],
                           'operation_id': ['This field is required.']}


@mock.patch('jco.appprocessor.notify.api_models')
def test_change_withdraw_address_request_notify_error(api_models, client, accounts):
    api_models.Notification.objects.create.side_effect = RuntimeError("DB Error")

    EmailAddress.objects.filter(email='user1@main.com').update(verified=True)
    client.authenticate('user1@main.com', 'password1')
    data = {'address': '0x3BA2E2565dB2c018aDd0b24483fE99fC2cCCDa8e'}
    resp = client.put('/api/withdraw-address/', data)
    assert resp.status_code == 500
    assert resp.json() == {'detail': 'Unexpected error, please try again'}

    assert 0 == models.Operation.objects.count()
    assert 0 == models.Notification.objects.count()


@mock.patch('jco.appprocessor.notify.api_models')
def test_withdraw_jnt_request_notify_error(api_models, client, accounts, settings, jnt):
    settings.WITHDRAW_AVAILABLE_SINCE = datetime.now()
    api_models.Notification.objects.create.side_effect = RuntimeError("DB Error")
    accounts[0].withdraw_address = '0x123'
    accounts[0].is_identity_verified = True
    accounts[0].save()

    EmailAddress.objects.filter(email='user1@main.com').update(verified=True)
    client.authenticate('user1@main.com', 'password1')
    data = {}
    resp = client.post('/api/withdraw-jnt/', data)

    assert resp.status_code == 500
    assert resp.json() == {'detail': 'Unexpected error, please try again'}

    assert 1 == models.Withdraw.objects.count()
    assert 0 == models.Operation.objects.count()
    assert 0 == models.Notification.objects.count()


def test_withdraw_jnt_request_kyc_not_verified(client, accounts, settings, jnt):
    settings.WITHDRAW_AVAILABLE_SINCE = datetime.now()
    accounts[0].withdraw_address = '0x123'
    accounts[0].is_identity_verified = False
    accounts[0].save()

    EmailAddress.objects.filter(email='user1@main.com').update(verified=True)
    client.authenticate('user1@main.com', 'password1')
    data = {}
    resp = client.post('/api/withdraw-jnt/', data)

    assert resp.status_code == 403
    assert resp.json() == {'detail': 'Please confirm your identity to withdraw JNT'}

    assert 0 == models.Withdraw.objects.count()
    assert 0 == models.Operation.objects.count()
    assert 0 == models.Notification.objects.count()

