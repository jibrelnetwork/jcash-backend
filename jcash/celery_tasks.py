from celery.schedules import crontab
from jcash.commonutils.app_init import initialize_app

import django
django.setup()

from jcash.commonutils.celery_lock import locked_task
from jcash.celeryapp import celery_app
from jcash.commonutils.currencyrates import fetch_currency_price, fetch_jnt_price
from jcash.appprocessor import commands


@celery_app.task()
@locked_task()
@initialize_app
def celery_fetch_tickers_price():
    return fetch_currency_price()


@celery_app.task()
@locked_task()
@initialize_app
def celery_process_all_notifications_runner():
    return commands.process_all_notifications_runner()


@celery_app.task()
@locked_task()
@initialize_app
def celery_check_document_verification_status_runner():
    return commands.check_document_verification_status_runner()


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
def celery_fetch_replenisher():
    return commands.fetch_replenisher()


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
    return commands.check_outgoing_transactions_runner()


@celery_app.task()
@locked_task()
@initialize_app
def celery_process_outgoing_transactions():
    return commands.process_outgoing_transactions_runner()


@celery_app.task()
@locked_task()
@initialize_app
def celery_check_address_licenses():
    return commands.check_address_licenses()


@celery_app.task()
@locked_task()
@initialize_app
def celery_fetch_currencies_state():
    return commands.fetch_currencies_state()


@celery_app.task()
@locked_task()
@initialize_app
def celery_fetch_jnt_price():
    return fetch_jnt_price()


@celery_app.task()
@locked_task()
@initialize_app
def celery_build_proof_of_solvency():
    return commands.build_proof_of_solvency()


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
    sender.add_periodic_task(1,
                             celery_process_all_notifications_runner,
                             expires=10,
                             name='process_all_notifications')
    sender.add_periodic_task(120,
                             celery_check_document_verification_status_runner,
                             expires=1 * 60,
                             name='check_document_verification_status_runner')
    sender.add_periodic_task(crontab(minute='*/1'),
                             celery_process_all_uncomplete_verifications,
                             expires=1 * 60,
                             name='process_all_uncomplete_verifications')
    sender.add_periodic_task(15,
                             celery_process_license_users_addresses,
                             expires=5 * 60,
                             name='process_license_users_addresses')
    sender.add_periodic_task(crontab(minute='*/1'),
                             celery_process_applications,
                             expires=1 * 60,
                             name='process_applications')
    sender.add_periodic_task(30,
                             celery_check_outgoing_transactions,
                             expires=1 * 60,
                             name='check_outgoing_transactions')
    sender.add_periodic_task(30,
                             celery_process_outgoing_transactions,
                             expires=1 * 60,
                             name='process_outgoing_transactions')
    sender.add_periodic_task(60,
                             celery_fetch_replenisher,
                             expires=1 * 60,
                             name='fetch_replenisher')
    sender.add_periodic_task(5,
                             celery_check_address_licenses,
                             expires=15,
                             name='check_address_licenses')
    sender.add_periodic_task(5,
                             celery_fetch_currencies_state,
                             expires=15,
                             name='fetch_currencies_state')
    sender.add_periodic_task(crontab(minute='*/15'),
                             celery_fetch_jnt_price,
                             expires=15,
                             name='fetch_jnt_price')
    sender.add_periodic_task(crontab(minute='*/15'),
                             celery_build_proof_of_solvency,
                             expires=15,
                             name='build_proof_of_solvency')
