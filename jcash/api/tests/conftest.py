from datetime import datetime
from dateutil.tz import tzlocal

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
                                    verified=True if user.email == 'user2@mail.local' or
                                                     user.email == 'user3@mail.local' or
                                                     user.email == 'user4@mail.local' else False)
    return users


@pytest.fixture
def accounts(users):
    _accounts = []
    for user in users:
        _accounts.append(models.Account.objects.create(user=user,
                                                       is_identity_verified=True if user.email == 'user2@mail.local' or
                                                                                    user.email == 'user4@mail.local' else False))
    return _accounts


@pytest.fixture
def customers(accounts):
    personal = models.Personal.objects.create(fullname='Ivan Ivanov', nationality='Russia', birthday='1900-01-01',
                                              phone='+1234567890', email=accounts[1].user.email, country='Russia',
                                              street='Rakhmanovskiy per', apartment='1', city='Moscow',
                                              postcode='123456', profession='composer', income_source='income_source',
                                              assets_origin='assets_origin', jcash_use='jcash_use',
                                              status=models.CustomerStatus.submitted, account=accounts[1])

    corporate = models.Corporate.objects.create(name='Alphabet', domicile_country='USA', business_phone='+123456789',
                                                business_email='info@alphabet.com', country='USA', street='Jones Street',
                                                apartment='1', city='NY', postcode='123456', industry='industry',
                                                assets_origin='assets_origin', currency_nature='currency_nature',
                                                assets_origin_description='assets_origin_description',
                                                jcash_use='jcash_use',
                                                contact_fullname='Petr Petrov', contact_birthday='1900-01-01',
                                                contact_nationality='USA', contact_residency='USA',
                                                contact_phone='+1234567890', contact_email=accounts[1].user.email,
                                                contact_street='Jones Street', contact_apartment='1', contact_city='NY',
                                                contact_postcode='123456', status=models.CustomerStatus.unavailable,
                                                account=accounts[1])

    return (personal, corporate)


@pytest.fixture
def addresses(accounts):
    return [
        models.Address.objects.create(address='0x281055afc982d96fab65b3a49cac8b878184cb16',
                                      type='eth',
                                      is_verified=True,
                                      is_allowed=True,
                                      user=accounts[1].user),
        models.Address.objects.create(address='0x6f46cf5569aefa1acc1009290c8e043747172d89',
                                      type='eth',
                                      is_verified=False,
                                      is_removed=True,
                                      is_allowed=False,
                                      user=accounts[1].user),
        models.Address.objects.create(address='0x90e63c3d53e0ea496845b7a03ec7548b70014a91',
                                      type='eth',
                                      is_verified=False,
                                      is_removed=False,
                                      is_allowed=False,
                                      user=accounts[1].user),
        models.Address.objects.create(address='0x53d284357ec70ce289d6d64134dfac8e511c8a3d',
                                      type='eth',
                                      is_verified=False,
                                      is_removed=True,
                                      is_allowed=False,
                                      user=accounts[1].user),
        models.Address.objects.create(address='0xab7c74abc0c4d48d1bdad5dcb26153fc8780f83e',
                                      type='eth',
                                      is_verified=True,
                                      is_removed=False,
                                      is_allowed=True,
                                      user=accounts[1].user),
    ]


@pytest.fixture
def currencies():
    curr_base = models.Currency.objects.create(display_name='ETH', symbol='eth', balance=999999.99)
    curr_rec = models.Currency.objects.create(display_name='jAED', symbol='aed', balance=999999.99)
    curr_pair = models.CurrencyPair.objects.create(display_name='ETH/jAED', symbol='ethjaed',
                                                   base_currency=curr_base, reciprocal_currency=curr_rec,
                                                   is_exchangeable=True, is_buyable=True, is_sellable=True)
    cur_pair_rate = models.CurrencyPairRate.objects.create(currency_pair=curr_pair, buy_price=1761.0, sell_price=1726.0,
                                           created_at=datetime.now(tzlocal()))
    return (curr_pair, curr_base, curr_rec, cur_pair_rate)


@pytest.fixture
def applications(accounts, addresses, currencies):
    return [
        models.Application.objects.create(user=accounts[1].user, address=addresses[0],
                                          currency_pair=currencies[0], base_currency='jAED',
                                          reciprocal_currency='ETH', currency_pair_rate=currencies[3],
                                          rate=currencies[3].buy_price, base_amount=1100,
                                          reciprocal_amount=1100/currencies[3].buy_price,
                                          is_active=False, exchanger_address='0x2bd05c677d007a22aaa9b9fa2eaec7a8cd09798d',
                                          is_reverse=True, status=str(models.ApplicationStatus.cancelled),
                                          created_at=datetime.now(tzlocal()), expired_at=datetime.now(tzlocal())),
        models.Application.objects.create(user=accounts[1].user, address=addresses[0],
                                          currency_pair=currencies[0], base_currency='ETH',
                                          reciprocal_currency='jAED', currency_pair_rate=currencies[3],
                                          rate=currencies[3].sell_price, base_amount=10,
                                          reciprocal_amount=10 * currencies[3].sell_price,
                                          is_active=True, exchanger_address='0x2bd05c677d007a22aaa9b9fa2eaec7a8cd09798d',
                                          is_reverse=False, status=models.ApplicationStatus.cancelled,
                                          created_at=datetime.now(tzlocal()), expired_at=datetime.now(tzlocal()))
        ]
