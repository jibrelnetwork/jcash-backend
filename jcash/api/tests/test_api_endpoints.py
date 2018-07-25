from datetime import datetime
from unittest import mock
import json
from io import BytesIO

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


def test_success_get_residential_countries(client, users):
    client.authenticate('user1@mail.local', 'password1')
    resp = client.get('/api/residential-countries/')
    assert resp.status_code == 200
    assert resp.json()['success'] == True
    assert len(resp.json()['countries']) == 3


def test_success_get_citizenship_countries(client, users):
    client.authenticate('user1@mail.local', 'password1')
    resp = client.get('/api/citizenship-countries/')
    assert resp.status_code == 200
    assert resp.json()['success'] == True
    assert len(resp.json()['countries']) == 198


def test_success_get_account_wo_customers(client, accounts):
    client.authenticate('user1@mail.local', 'password1')
    resp = client.get('/api/account/')
    assert resp.status_code == 200
    assert resp.json()['success'] == True
    assert 'username' in resp.json()
    assert 'fullname' in resp.json()
    assert 'birthday' in resp.json()
    assert 'nationality' in resp.json()
    assert 'residency' in resp.json()
    assert 'is_email_confirmed' in resp.json()
    assert 'status' in resp.json()
    assert 'customers' in resp.json()
    assert resp.json()['customers'] == []


def test_success_get_account_w_customers(client, customers):
    client.authenticate('user2@mail.local', 'password2')
    resp = client.get('/api/account/')
    assert resp.status_code == 200
    assert resp.json()['success'] == True
    assert resp.json()['username'] == 'user2@mail.local'
    assert resp.json()['fullname'] == 'Ivan Ivanov'
    assert resp.json()['birthday'] == '1900-01-01'
    assert resp.json()['nationality'] == 'Russia'
    assert resp.json()['residency'] == 'Russia'
    assert resp.json()['is_email_confirmed'] == True
    assert resp.json()['status'] == 'verified'
    assert 'customers' in resp.json()
    assert len(resp.json()['customers']) == 2
    assert resp.json()['customers'][0]['type'] == 'personal'
    assert 'uuid' in resp.json()['customers'][0]
    assert resp.json()['customers'][0]['status'] == 'submitted'
    assert resp.json()['customers'][1]['type'] == 'corporate'
    assert 'uuid' in resp.json()['customers'][1]
    assert resp.json()['customers'][1]['status'] == 'unavailable'


def test_success_get_address_user_w_no_addresses(client, addresses):
    client.authenticate('user1@mail.local', 'password1')
    resp = client.get('/api/address/')
    assert resp.status_code == 200
    assert resp.json()['success'] == True
    assert resp.json()['addresses'] == []


def test_success_get_address_user_w_addresses(client, addresses):
    client.authenticate('user2@mail.local', 'password2')
    resp = client.get('/api/address/')
    assert resp.status_code == 200
    assert resp.json()['success'] == True
    assert len(resp.json()['addresses']) == 3
    assert resp.json()['addresses'][0]['address'] == '0xab7c74abc0c4d48d1bdad5dcb26153fc8780f83e'
    assert resp.json()['addresses'][0]['type'] == 'eth'
    assert resp.json()['addresses'][0]['is_verified'] == True
    assert resp.json()['addresses'][1]['address'] == '0x90e63c3d53e0ea496845b7a03ec7548b70014a91'
    assert resp.json()['addresses'][1]['type'] == 'eth'
    assert resp.json()['addresses'][1]['is_verified'] == False
    assert resp.json()['addresses'][2]['address'] == '0x281055afc982d96fab65b3a49cac8b878184cb16'
    assert resp.json()['addresses'][2]['type'] == 'eth'
    assert resp.json()['addresses'][2]['is_verified'] == True


def test_fail_post_address_wo_address(client, addresses):
    client.authenticate('user2@mail.local', 'password2')
    resp = client.post('/api/address/',
                       json.dumps({'type': 'eth'}),
                       headers={'content-type': 'application/json'})
    assert resp.status_code != 200
    assert resp.json()['success'] == False
    assert 'errors' in resp.json()
    assert 'address' in resp.json()['errors']


def test_fail_post_address_wo_type(client, addresses):
    client.authenticate('user2@mail.local', 'password2')
    resp = client.post('/api/address/',
                       json.dumps({'address':'0xc6d7cd473add4ebfbb4fb1cfdd6ad310313a61c9'}),
                       headers={'content-type': 'application/json'})
    assert resp.status_code != 200
    assert resp.json()['success'] == False
    assert 'errors' in resp.json()
    assert 'type' in resp.json()['errors']


def test_fail_post_address_not_verified_email(client, addresses):
    client.authenticate('user1@mail.local', 'password1')
    resp = client.post('/api/address/',
                       json.dumps({'address':'0xc6d7cd473add4ebfbb4fb1cfdd6ad310313a61c9', 'type': 'eth'}),
                       headers={'content-type': 'application/json'})
    assert resp.status_code != 200
    assert resp.json()['success'] == False
    assert 'error' in resp.json()
    assert 'confirm the e-mail' in resp.json()['error']


def test_fail_post_address_not_approved_personal_data(client, addresses):
    client.authenticate('user3@mail.local', 'password3')
    resp = client.post('/api/address/',
                       json.dumps({'address':'0xc6d7cd473add4ebfbb4fb1cfdd6ad310313a61c9', 'type': 'eth'}),
                       headers={'content-type': 'application/json'})
    assert resp.status_code != 200
    assert resp.json()['success'] == False
    assert 'error' in resp.json()
    assert 'not verified' in resp.json()['error']


def test_fail_post_address_wrong_address(client, addresses):
    client.authenticate('user2@mail.local', 'password2')
    resp = client.post('/api/address/',
                       json.dumps({'address':'0xc6d7cd473add4ebfbb4fb1cfdd6ad310313a61c', 'type': 'eth'}),
                       headers={'content-type': 'application/json'})
    assert resp.status_code != 200
    assert resp.json()['success'] == False
    assert 'error' in resp.json()
    assert 'Ethereum' in resp.json()['error']


def test_fail_post_address_exist(client, addresses):
    client.authenticate('user2@mail.local', 'password2')
    resp = client.post('/api/address/',
                       json.dumps({'address':'0xab7c74abc0c4d48d1bdad5dcb26153fc8780f83e', 'type': 'eth'}),
                       headers={'content-type': 'application/json'})
    assert resp.status_code != 200
    assert resp.json()['success'] == False
    assert 'error' in resp.json()
    assert 'exist' in resp.json()['error']


def test_post_address(client, addresses):
    client.authenticate('user2@mail.local', 'password2')

    # add fourth address
    address = '0xc6d7cd473add4ebfbb4fb1cfdd6ad310313a61c9'
    resp = client.post('/api/address/',
                       json.dumps({'address': address, 'type': 'eth'}),
                       headers={'content-type': 'application/json'})
    assert resp.status_code == 200
    assert resp.json()['success'] == True
    assert resp.json()['address'] == address
    assert resp.json()['type'] == 'eth'
    assert 'of the address ' + address in resp.json()['message']
    assert len(resp.json()['uuid']) > 0

    # add fifth address
    resp = client.post('/api/address/',
                       json.dumps({'address': '0x742d35cc6634c0532925a3b844bc454e4438f44e', 'type': 'eth'}),
                       headers={'content-type': 'application/json'})
    assert resp.status_code == 200

    # check addresses count
    resp = client.get('/api/address')
    assert resp.status_code == 200
    assert len(resp.json()['addresses']) == 5

    # add sixth address
    resp = client.post('/api/address/',
                       json.dumps({'address': '0xfe9e8709d3215310075d67e3ed32a380ccf451c8', 'type': 'eth'}),
                       headers={'content-type': 'application/json'})
    assert resp.status_code != 200
    assert resp.json()['success'] == False
    assert 'Too many addresses' in resp.json()['error']


def test_fail_address_remove_user_have_no_addresses(client, addresses):
    client.authenticate('user4@mail.local', 'password4')

    resp = client.post('/api/address-remove/',
                       json.dumps({'address': '0xc6d7cd473add4ebfbb4fb1cfdd6ad310313a61c9'}),
                       headers={'content-type': 'application/json'})
    assert resp.status_code != 200
    assert resp.json()['success'] == False
    assert 'exist' in resp.json()['error']


def test_fail_address_remove_non_ownable_address(client, addresses):
    client.authenticate('user4@mail.local', 'password4')

    resp = client.post('/api/address-remove/',
                       json.dumps({'address': '0x281055afc982d96fab65b3a49cac8b878184cb16'}),
                       headers={'content-type': 'application/json'})
    assert resp.status_code != 200
    assert resp.json()['success'] == False
    assert 'exist' in resp.json()['error']


def test_fail_address_remove_wo_address(client, addresses):
    client.authenticate('user4@mail.local', 'password4')

    resp = client.post('/api/address-remove/',
                       json.dumps({}),
                       headers={'content-type': 'application/json'})
    assert resp.status_code != 200
    assert resp.json()['success'] == False
    assert 'address' in resp.json()['errors']


def test_get_currencies(client, users, currencies):
    client.authenticate('user4@mail.local', 'password4')
    resp = client.get('/api/currency/')
    assert resp.status_code == 200
    assert resp.json()['success'] == True
    assert len(resp.json()['currencies']) == 2

    # check first currency
    assert resp.json()['currencies'][0]['base_currency'] == 'ETH'
    assert resp.json()['currencies'][0]['rec_currency'] == 'jAED'
    assert resp.json()['currencies'][0]['round_digits'] == 8
    assert resp.json()['currencies'][0]['min_limit'] == 0.0
    assert resp.json()['currencies'][0]['max_limit'] == 999999999.0

    # check second currency
    assert resp.json()['currencies'][1]['base_currency'] == 'jAED'
    assert resp.json()['currencies'][1]['rec_currency'] == 'ETH'
    assert resp.json()['currencies'][1]['round_digits'] == 8
    assert resp.json()['currencies'][1]['min_limit'] == 0.0
    assert resp.json()['currencies'][1]['max_limit'] == 999999999.0


def test_get_currency_rates(live_server, currencies):
    client = ApiClient(base_url=live_server)
    resp = client.get('/api/currency-rates/')
    assert resp.status_code == 200
    assert resp.json()['success'] == True
    assert len(resp.json()['currencies']) == 1

    # check first currency rate
    assert resp.json()['currencies'][0]['base_currency'] == 'ETH'
    assert resp.json()['currencies'][0]['rec_currency'] == 'jAED'
    assert resp.json()['currencies'][0]['rate_buy'] > 0
    assert resp.json()['currencies'][0]['rate_sell'] > 0
    assert resp.json()['currencies'][0]['rate_buy'] > resp.json()['currencies'][0]['rate_sell']


def test_success_get_currency_rate_by_base_amount1(client, users, currencies):
    client.authenticate('user4@mail.local', 'password4')

    resp = client.post('/api/currency-rate/',
                       json.dumps({'base_currency': 'ETH', 'rec_currency': 'jAED', 'base_amount': 1000.0}),
                       headers={'content-type': 'application/json'})
    assert resp.status_code == 200
    assert resp.json()['success'] == True
    assert len(resp.json()['uuid']) > 0
    assert resp.json()['rate'] == 1726.0
    assert resp.json()['rec_amount'] == 1726000.0
    assert resp.json()['base_amount'] == 1000.0


def test_success_get_currency_rate_by_rec_amount1(client, users, currencies):
    client.authenticate('user4@mail.local', 'password4')

    resp = client.post('/api/currency-rate/',
                       json.dumps({'base_currency': 'ETH', 'rec_currency': 'jAED', 'rec_amount': 4000.0}),
                       headers={'content-type': 'application/json'})
    assert resp.status_code == 200
    assert resp.json()['success'] == True
    assert len(resp.json()['uuid']) > 0
    assert resp.json()['rate'] == 1726.0
    assert resp.json()['rec_amount'] == 4000.0
    assert resp.json()['base_amount'] == 2.3174971


def test_success_get_currency_rate_by_base_amount2(client, users, currencies):
    client.authenticate('user4@mail.local', 'password4')

    resp = client.post('/api/currency-rate/',
                       json.dumps({'base_currency': 'jAED', 'rec_currency': 'ETH', 'base_amount': 4000.0}),
                       headers={'content-type': 'application/json'})
    assert resp.status_code == 200
    assert resp.json()['success'] == True
    assert len(resp.json()['uuid']) > 0
    assert resp.json()['rate'] == 0.0005678591709256105
    assert resp.json()['rec_amount'] == 2.27143668
    assert resp.json()['base_amount'] == 4000.0


def test_success_get_currency_rate_by_rec_amount2(client, users, currencies):
    client.authenticate('user4@mail.local', 'password4')
    resp = client.post('/api/currency-rate/',
                       json.dumps({'base_currency': 'jAED', 'rec_currency': 'ETH', 'rec_amount': 1000.0}),
                       headers={'content-type': 'application/json'})
    assert resp.status_code == 200
    assert resp.json()['success'] == True
    assert len(resp.json()['uuid']) > 0
    assert resp.json()['rate'] == 0.0005678591709256105
    assert resp.json()['rec_amount'] == 1000.0
    assert resp.json()['base_amount'] == 1761000.0


def test_get_application(client, accounts, currencies, applications):
    client.authenticate('user2@mail.local', 'password2')
    resp = client.get('/api/application/')
    assert resp.status_code == 200
    assert resp.json()['success'] == True
    assert len(resp.json()['application']) == 2

    # check first time application
    assert len(resp.json()['application'][1]['app_uuid']) > 0
    assert 'created_at' in resp.json()['application'][1]
    assert 'expired_at' in resp.json()['application'][1]
    assert 'incoming_tx_id' in resp.json()['application'][1]
    assert 'outgoing_tx_id' in resp.json()['application'][1]
    assert 'incoming_tx_value' in resp.json()['application'][1]
    assert 'outgoing_tx_value' in resp.json()['application'][1]
    assert resp.json()['application'][1]['source_address'] == '0x281055afc982d96fab65b3a49cac8b878184cb16'
    assert resp.json()['application'][1]['exchanger_address'] == '0x2bd05c677d007a22aaa9b9fa2eaec7a8cd09798d'
    assert resp.json()['application'][1]['base_currency'] == 'jAED'
    assert resp.json()['application'][1]['base_amount'] == 1100.00
    assert resp.json()['application'][1]['reciprocal_currency'] == 'ETH'
    assert resp.json()['application'][1]['reciprocal_amount_actual'] == 0.624645088018172
    assert resp.json()['application'][1]['reciprocal_amount'] == 0.624645088018172
    assert resp.json()['application'][1]['rate'] == 0.0005678591709256105
    assert resp.json()['application'][1]['is_active'] == False
    assert resp.json()['application'][1]['is_reverse'] == True


def test_application(client, accounts, currencies, addresses, applications):
    client.authenticate('user2@mail.local', 'password2')

    # check that active application can be only one
    resp = client.post('/api/application/',
                       json.dumps({'address': addresses[0].address,
                                   'base_currency': 'ETH',
                                   'rec_currency': 'jAED',
                                   'base_amount': 1000.0,
                                   'uuid': str(currencies[3].pk)}),
                       headers={'content-type': 'application/json'})
    assert resp.status_code != 200
    assert resp.json()['success'] == False
    assert 'active application' in resp.json()['error']

    #check application count
    resp = client.get('/api/application/')
    assert len(resp.json()['application']) == 2

    # finish an application
    resp = client.post('/api/application-finish/',
                       json.dumps({'app_uuid': str(applications[1].pk)}),
                       headers={'content-type': 'application/json'})
    assert resp.status_code == 200
    assert resp.json()['success'] == True

    #check application is active
    resp = client.get('/api/application/')
    assert resp.json()['application'][0]['is_active'] == False

    # try to create new application
    resp = client.post('/api/application/',
                       json.dumps({'address': addresses[0].address,
                                   'base_currency': 'ETH',
                                   'rec_currency': 'jAED',
                                   'base_amount': 1000.0,
                                   'uuid': str(currencies[3].pk)}),
                       headers={'content-type': 'application/json'})
    assert resp.status_code == 200
    assert resp.json()['success'] == True
    app_uuid = resp.json()['app_uuid']

    # check application count
    resp = client.get('/api/application/')
    assert len(resp.json()['application']) == 3
    assert resp.json()['application'][0]['status'] == 'created'

    #check cancel operation
    resp = client.post('/api/application-cancel/',
                       json.dumps({'app_uuid': app_uuid}),
                       headers={'content-type': 'application/json'})
    assert resp.status_code == 200
    assert resp.json()['success'] == True


def test_success_customer_personal_contact_info(client, accounts):
    client.authenticate('user3@mail.local', 'password3')
    resp = client.post('/api/customer/personal/contact-info/',
                       json.dumps({'fullname': 'Ivanov Ivan',
                                   'nationality': 'Albania',
                                   'birthday': '1990-01-01',
                                   'phone': '+123456789',
                                   'email': 'ivanov_ivan@test.com'}),
                       headers={'content-type': 'application/json'})
    assert resp.status_code == 200
    assert resp.json()['success'] == True


def test_fail_customer_personal_contact_info(client, accounts):
    client.authenticate('user3@mail.local', 'password3')
    resp = client.post('/api/customer/personal/contact-info/',
                       json.dumps({}),
                       headers={'content-type': 'application/json'})
    assert resp.status_code != 200
    assert resp.json()['success'] == False
    assert 'fullname' in resp.json()['errors']
    assert 'nationality' in resp.json()['errors']
    assert 'birthday' in resp.json()['errors']
    assert 'phone' in resp.json()['errors']
    assert 'email' in resp.json()['errors']


def test_success_customer_personal_address_w_apartment(client, accounts):
    client.authenticate('user3@mail.local', 'password3')
    resp = client.post('/api/customer/personal/address/',
                       json.dumps({'country': 'Germany',
                                   'street': 'street_name',
                                   'apartment': '1',
                                   'city': 'Berlin',
                                   'postcode': '123456'}),
                       headers={'content-type': 'application/json'})
    assert resp.status_code == 200
    assert resp.json()['success'] == True


def test_success_customer_personal_address_wo_apartment(client, accounts):
    client.authenticate('user3@mail.local', 'password3')
    resp = client.post('/api/customer/personal/address/',
                       json.dumps({'country': 'Germany',
                                   'street': 'street_name',
                                   'city': 'Berlin',
                                   'postcode': '123456'}),
                       headers={'content-type': 'application/json'})
    assert resp.status_code == 200
    assert resp.json()['success'] == True


def test_fail_customer_personal_address_w_apartment(client, accounts):
    client.authenticate('user3@mail.local', 'password3')
    resp = client.post('/api/customer/personal/address/',
                       json.dumps({}),
                       headers={'content-type': 'application/json'})
    assert resp.status_code != 200
    assert resp.json()['success'] == False
    assert 'country' in resp.json()['errors']
    assert 'street' in resp.json()['errors']
    assert 'city' in resp.json()['errors']
    assert 'postcode' in resp.json()['errors']


def test_success_personal_income_info(client, accounts):
    client.authenticate('user3@mail.local', 'password3')
    resp = client.post('/api/customer/personal/income-info/',
                       json.dumps({'profession': 'profession',
                                   'income_source': 'income_source',
                                   'assets_origin': 'assets_origin',
                                   'jcash_use': 'jcash_use'}),
                       headers={'content-type': 'application/json'})
    assert resp.status_code == 200
    assert resp.json()['success'] == True


def test_fail_personal_income_info(client, accounts):
    client.authenticate('user3@mail.local', 'password3')
    resp = client.post('/api/customer/personal/income-info/',
                       json.dumps({}),
                       headers={'content-type': 'application/json'})
    assert resp.status_code != 200
    assert resp.json()['success'] == False
    assert 'profession' in resp.json()['errors']
    assert 'income_source' in resp.json()['errors']
    assert 'assets_origin' in resp.json()['errors']
    assert 'jcash_use' in resp.json()['errors']


def test_fail_personal_documents(client, accounts):
    client.authenticate('user3@mail.local', 'password3')
    resp = client.post('/api/customer/corporate/documents/',
                       data={},
                       headers={'content-type': 'multipart/form-data'})
    assert resp.status_code != 200
    assert resp.json()['success'] == False
    assert 'passport' in resp.json()['errors']
    assert 'selfie' in resp.json()['errors']
    assert 'utilitybills' in resp.json()['errors']


def test_success_corporate_company_info(client, accounts):
    client.authenticate('user3@mail.local', 'password3')
    resp = client.post('/api/customer/corporate/company-info/',
                       json.dumps({'name': 'business_name',
                                   'domicile_country': 'Germany',
                                   'phone': '+123456789',
                                   'email': 'info@business.com'}),
                       headers={'content-type': 'application/json'})
    assert resp.status_code == 200
    assert resp.json()['success'] == True


def test_fail_corporate_company_info(client, accounts):
    client.authenticate('user3@mail.local', 'password3')
    resp = client.post('/api/customer/corporate/company-info/',
                       json.dumps({}),
                       headers={'content-type': 'application/json'})
    assert resp.status_code != 200
    assert resp.json()['success'] == False
    assert 'name' in resp.json()['errors']
    assert 'domicile_country' in resp.json()['errors']
    assert 'phone' in resp.json()['errors']
    assert 'email' in resp.json()['errors']


def test_success_corporate_address_w_apartment(client, accounts):
    client.authenticate('user3@mail.local', 'password3')
    resp = client.post('/api/customer/corporate/address/',
                       json.dumps({'country': 'Germany',
                                   'street': 'Street name',
                                   'apartment': '1',
                                   'city': 'Berlin',
                                   'postcode': '123456'}),
                       headers={'content-type': 'application/json'})
    assert resp.status_code == 200
    assert resp.json()['success'] == True


def test_success_corporate_address_wo_apartment(client, accounts):
    client.authenticate('user3@mail.local', 'password3')
    resp = client.post('/api/customer/corporate/address/',
                       json.dumps({'country': 'Germany',
                                   'street': 'Street name',
                                   'city': 'Berlin',
                                   'postcode': '123456'}),
                       headers={'content-type': 'application/json'})
    assert resp.status_code == 200
    assert resp.json()['success'] == True


def test_fail_corporate_address(client, accounts):
    client.authenticate('user3@mail.local', 'password3')
    resp = client.post('/api/customer/corporate/address/',
                       json.dumps({}),
                       headers={'content-type': 'application/json'})
    assert resp.status_code != 200
    assert resp.json()['success'] == False
    assert 'country' in resp.json()['errors']
    assert 'street' in resp.json()['errors']
    assert 'city' in resp.json()['errors']
    assert 'postcode' in resp.json()['errors']


def test_success_corporate_income_info(client, accounts):
    client.authenticate('user3@mail.local', 'password3')
    resp = client.post('/api/customer/corporate/income-info/',
                       json.dumps({'industry': 'industry',
                                   'currency_nature': 'currency_nature',
                                   'assets_origin': 'assets_origin',
                                   'assets_origin_description': 'assets_origin_description',
                                   'jcash_use': 'jcash_use'}),
                       headers={'content-type': 'application/json'})
    assert resp.status_code == 200
    assert resp.json()['success'] == True


def test_fail_corporate_income_info(client, accounts):
    client.authenticate('user3@mail.local', 'password3')
    resp = client.post('/api/customer/corporate/income-info/',
                       json.dumps({}),
                       headers={'content-type': 'application/json'})
    assert resp.status_code != 200
    assert resp.json()['success'] == False
    assert 'industry' in resp.json()['errors']
    assert 'currency_nature' in resp.json()['errors']
    assert 'assets_origin' in resp.json()['errors']
    assert 'assets_origin_description' in resp.json()['errors']
    assert 'jcash_use' in resp.json()['errors']


def test_success_customer_corporate_contact_info_w_apartment(client, accounts):
    client.authenticate('user3@mail.local', 'password3')
    resp = client.post('/api/customer/corporate/contact-info/',
                       json.dumps({'fullname': 'Ivanov Ivan',
                                   'birthday': '1990-01-01',
                                   'email': 'ivanov_ivan@test.com',
                                   'nationality': 'Albania',
                                   'residency': 'Germany',
                                   'street': 'street name',
                                   'apartment': '1',
                                   'city': 'Berlin',
                                   'postcode': '123456',
                                   'phone': '+123456789'
                                   }),
                       headers={'content-type': 'application/json'})
    assert resp.status_code == 200
    assert resp.json()['success'] == True


def test_success_customer_corporate_contact_info_wo_apartment(client, accounts):
    client.authenticate('user3@mail.local', 'password3')
    resp = client.post('/api/customer/corporate/contact-info/',
                       json.dumps({'fullname': 'Ivanov Ivan',
                                   'birthday': '1990-01-01',
                                   'email': 'ivanov_ivan@test.com',
                                   'nationality': 'Albania',
                                   'residency': 'Germany',
                                   'street': 'street name',
                                   'city': 'Berlin',
                                   'postcode': '123456',
                                   'phone': '+123456789'
                                   }),
                       headers={'content-type': 'application/json'})
    assert resp.status_code == 200
    assert resp.json()['success'] == True


def test_fail_customer_corporate_contact_info(client, accounts):
    client.authenticate('user3@mail.local', 'password3')
    resp = client.post('/api/customer/corporate/contact-info/',
                       json.dumps({}),
                       headers={'content-type': 'application/json'})
    assert resp.status_code != 200
    assert resp.json()['success'] == False
    assert 'fullname' in resp.json()['errors']
    assert 'birthday' in resp.json()['errors']
    assert 'email' in resp.json()['errors']
    assert 'nationality' in resp.json()['errors']
    assert 'residency' in resp.json()['errors']
    assert 'street' in resp.json()['errors']
    assert 'city' in resp.json()['errors']
    assert 'postcode' in resp.json()['errors']
    assert 'phone' in resp.json()['errors']


def test_fail_corporate_documents(client, accounts):
    client.authenticate('user3@mail.local', 'password3')
    resp = client.post('/api/customer/corporate/documents/',
                       data={},
                       headers={'content-type': 'multipart/form-data'})
    assert resp.status_code != 200
    assert resp.json()['success'] == False
    assert 'passport' in resp.json()['errors']
    assert 'selfie' in resp.json()['errors']
    assert 'utilitybills' in resp.json()['errors']
