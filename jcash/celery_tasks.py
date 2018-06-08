from celery.schedules import crontab
from jcash.commonutils.app_init import initialize_app

import django
django.setup()

from jcash.commonutils.celery_lock import locked_task
from jcash.celeryapp import celery_app
from jcash.commonutils.currencyrates import feth_currency_price
from jcash.appprocessor import commands


@celery_app.task()
@locked_task()
@initialize_app
def celery_fetch_tickers_price():
    return feth_currency_price()


@celery_app.task()
@locked_task()
@initialize_app
def celery_process_all_notifications_runner():
    return commands.process_all_notifications_runner()


@celery_app.task()
@locked_task()
@initialize_app
def celery_process_all_uncomplete_verifications():
    return commands.process_all_uncomplete_verifications()


@celery_app.task()
@locked_task()
@initialize_app
def celery_fetch_eth_events():
    return commands.fetch_eth_events()


@celery_app.task()
@locked_task()
@initialize_app
def celery_process_linked_unconfirmed_events():
    return commands.process_linked_unconfirmed_events()


@celery_app.task()
@locked_task()
@initialize_app
def celery_process_unlinked_unconfirmed_events():
    return commands.process_unlinked_unconfirmed_events()


@celery_app.task()
@locked_task()
@initialize_app
def celery_process_license_users_addresses():
    return commands.process_license_users_addresses()


@celery_app.task()
@locked_task()
@initialize_app
def celery_process_applications():
    return commands.process_applications()


@celery_app.task()
@locked_task()
@initialize_app
def celery_check_outgoing_transactions():
    return commands.check_outgoing_transactions()


@celery_app.on_after_finalize.connect
def setup_periodic_tasks(sender, **kwargs):
    sender.add_periodic_task(crontab(minute='*/1'),
                             celery_fetch_tickers_price,
                             expires=1 * 60,
                             name='fetch_tickers_price')
    sender.add_periodic_task(crontab(minute='*/1'),
                             celery_fetch_eth_events,
                             expires=1 * 60,
                             name='fetch_eth_events')
    sender.add_periodic_task(30,
                             celery_process_linked_unconfirmed_events,
                             expires=1 * 60,
                             name='process_linked_unconfirmed_events')
    sender.add_periodic_task(30,
                             celery_process_unlinked_unconfirmed_events,
                             expires=1 * 60,
                             name='process_unlinked_unconfirmed_events')
    sender.add_periodic_task(20,
                             celery_process_all_notifications_runner,
                             expires=1 * 60,
                             name='process_all_notifications')
    sender.add_periodic_task(crontab(minute='*/1'),
                             celery_process_all_uncomplete_verifications,
                             expires=1 * 60,
                             name='process_all_uncomplete_verifications')
    sender.add_periodic_task(crontab(minute='*/1'),
                             celery_process_license_users_addresses,
                             expires=1 * 60,
                             name='process_license_users_addresses')
    sender.add_periodic_task(crontab(minute='*/1'),
                             celery_process_applications,
                             expires=1 * 60,
                             name='process_applications')
    sender.add_periodic_task(crontab(minute='*/1'),
                             celery_check_outgoing_transactions,
                             expires=1 * 60,
                             name='check_outgoing_transactions')
