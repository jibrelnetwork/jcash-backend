import logging
import sys
import json
import traceback
from datetime import datetime, timedelta
from dateutil.tz import tzlocal
import time

from django.db import transaction
from django.db.models import Q, F, Count
from django.contrib.auth import get_user_model
from django.utils import timezone

from jcash.api.models import (
    Document,
    Notification,
    IncomingTransaction,
    Currency,
    TransactionStatus,
    Address,
    Application,
    ApplicationStatus,
    Refund,
    Exchange,
    Replenisher,
    DocumentVerification,
)
from jcash.commonutils import (
    notify,
    person_verify,
    eth_events,
    eth_contracts,
    eth_utils,
    math,
    exchange_utils as utils,
    ga_integration,
)
from jcash.api.tasks import celery_refund_eth, celery_transfer_eth, celery_refund_token, celery_transfer_token
from jcash.settings import (
    LOGIC__MAX_VERIFICATION_ATTEMPTS,
    ETH_TX__BLOCKS_CONFIRM_NUM,
    LOGIC__MAX_DIFF_PERCENT,
    LOGIC__EXPIRATION_LIMIT_SEC,
    LOGIC__REFUND_FEE_PERCENT,
    ETH_TX__MAX_PENDING_TX_COUNT
)


logger = logging.getLogger(__name__)


def process_all_notifications_runner():
    logger.info('Run notifications processing')

    notifications_to_send = Notification.objects.filter(is_sended=False).all()
    for notification in notifications_to_send:
        success, message_id = notify.send_notification(notification.pk)
        notification.is_sended = success
        notification.meta['mailgun_message_id'] = message_id

        notification.save()

    logger.info('Finished notifications processing')


def get_document_verification(document: Document) -> DocumentVerification:
    """
    Get latest document verification
    :param document: Document
    :return: DocumentVerification
    """
    doc_verification = None

    if hasattr(document, Document.rel_selfie_verification):
        doc_verification = document.selfie_verification
    elif hasattr(document, Document.rel_utilitybills_verification):
        doc_verification = document.utilitybills_verification
    elif hasattr(document, Document.rel_passport_verification):
        doc_verification = document.passport_verification

    return doc_verification


def check_document_verification_status(document_id):
    """
    Check and store OnFido check status and result
    """
    document = Document.objects.get(pk=document_id)
    logger.info('Checking verification status for document id=%s', document_id)
    if document.onfido_check_status == person_verify.STATUS_COMPLETE:
        logger.warn('Verification completed')
        return
    api = person_verify.get_client()

    doc_verification = get_document_verification(document)

    if doc_verification:
        with transaction.atomic():
            check = api.find_check(doc_verification.onfido_applicant_id, document.onfido_check_id)
            logger.info('Verification status is: %s, result: %s', check.status, check.result)
            document.onfido_check_status = check.status
            document.onfido_check_result = check.result
            document.save()


def check_document_verification_status_runner():
    documents_to_check = Document.objects.filter(onfido_check_result=None).exclude(onfido_check_id=None).all()
    for document in documents_to_check:
        logger.info('Run check verification status for document id=%s', document.pk)
        check_document_verification_status(document.pk)


def verify_document(document_id):
    """
    Create OnFido check to verify customer document
    """
    with transaction.atomic():
        now = timezone.now()
        document = Document.objects.select_for_update().get(id=document_id)

        if document.onfido_check_status == person_verify.STATUS_COMPLETE:
            logger.warn('Verification completed for id %s, exiting', document.pk)
            return

        if document.onfido_check_id is not None:
            logger.warn('Check exists for id %s, exiting', document.pk)
            return

        if (document.verification_started_at and
            (now - document.verification_started_at) < timedelta(minutes=5)):
            logger.info('Verification already started for id %s, exiting', document.pk)
            return

        logger.info('Start verifying process for id %s', document.pk)
        document.verification_started_at = now
        document.verification_attempts += 1
        document.save()

    doc_verification = get_document_verification(document)
    if doc_verification:
        with transaction.atomic():
            if not doc_verification.onfido_applicant_id:
                if doc_verification.personal:
                    full_name = doc_verification.personal.fullname
                    first_name = full_name.split(" ")[0]
                    last_name = full_name.split(" ")[1] if len(full_name.split(" "))>1 else ""
                    birtday = doc_verification.personal.birthday
                elif doc_verification.corporate:
                    full_name = doc_verification.corporate.contact_fullname
                    first_name = full_name.split(" ")[0]
                    last_name = full_name.split(" ")[1] if len(full_name.split(" "))>1 else ""
                    birtday = doc_verification.corporate.contact_birthday
                else:
                    logger.error('Document verification id=%s has no customer', doc_verification.pk)
                    return

                email = doc_verification.user.email
                applicant_id = person_verify.create_applicant(first_name, last_name, email, birtday)
                doc_verification.onfido_applicant_id = applicant_id
                doc_verification.save()
                logger.info('Applicant %s created for %s', doc_verification.onfido_applicant_id,
                            doc_verification.user.username)
            else:
                logger.info('Applicant for %s already exists: %s', doc_verification.user.username,
                            doc_verification.onfido_applicant_id)

            if not document.onfido_document_id:
                document_id = person_verify.upload_document(doc_verification.onfido_applicant_id,
                                                            document.image.path,
                                                            document.ext,
                                                            document.type)
                document.onfido_document_id = document_id
                document.save()
                logger.info('Document for %s uploaded: %s', document.user.username, document.onfido_document_id)
            else:
                logger.info('Document for %s already uploaded: %s', document.user.username, document.onfido_document_id)

            check_id = person_verify.create_check(doc_verification.onfido_applicant_id)
            document.onfido_check_id = check_id
            document.onfido_check_created = timezone.now()
            document.save()
            logger.info('Check for %s created: %s', document.user.username, document.onfido_check_id)


def process_all_uncomplete_verifications():
    logger.info('Run process uncomplete verifications')

    now = datetime.now()
    condition = (
        Q(onfido_check_id=None) &
        Q(verification_attempts__lt=LOGIC__MAX_VERIFICATION_ATTEMPTS) &
        ~Q(image='') &
        (Q(verification_started_at__lt=(now - timedelta(minutes=5))) |
         Q(verification_started_at=None))
    )
    documents_to_verify = Document.objects.filter(condition).all()
    for document in documents_to_verify:
        logger.info('Retry uncomplete document verification %s', document.pk)
        verify_document(document.pk)

    logger.info('Finished process uncomplete verifications')


def get_borrow_fee(in_value):
    return LOGIC__REFUND_FEE_PERCENT * in_value / 100


def process_unlinked_unconfirmed_events():
    logger.info('Run process unlinked unconfirmed events')

    in_txs = IncomingTransaction.objects.filter(Q(status=TransactionStatus.not_confirmed) &
                                                Q(created_at__lte=timezone.now()+timedelta(LOGIC__EXPIRATION_LIMIT_SEC)) &
                                                Q(application=None) &
                                                Q(is_linked=False))
    for in_tx in in_txs:
        tx_info = eth_events.get_tx_info(in_tx.transaction_id)
        try:
            with transaction.atomic():
                if tx_info[0] is not None and tx_info[1] >= in_tx.block_height + ETH_TX__BLOCKS_CONFIRM_NUM:
                    in_tx.status = TransactionStatus.confirmed
                    refund_value = in_tx.value - get_borrow_fee(in_tx.value)
                    if refund_value < 0:
                        logger.error('outgoing tx value < 0')
                    refund = Refund.objects.create(created_at=datetime.now(tzlocal()),
                                                   incoming_transaction_id=in_tx.pk,
                                                   currency_id=in_tx.currency.pk,
                                                   to_address=in_tx.from_address,
                                                   value=refund_value,
                                                   status=TransactionStatus.confirmed)
                    refund.save()
                elif tx_info[0] is None:
                    in_tx.status = TransactionStatus.rejected

                in_tx.save()
        except:
            exception_str = ''.join(traceback.format_exception(*sys.exc_info()))
            logging.getLogger(__name__).error("Failed to process unlinked incoming tx \"{}\" due to error:\n{}"
                                                .format(in_tx.transaction_id, exception_str))

    logger.info('Finished process unlinked unconfirmed events')


def process_linked_unconfirmed_events():
    logger.info('Run process linked unconfirmed events')

    in_txs = IncomingTransaction.objects.filter(Q(status=TransactionStatus.not_confirmed) &
                                                ~Q(application=None))
    for in_tx in in_txs:
        tx_info = eth_events.get_tx_info(in_tx.transaction_id)
        try:
            with transaction.atomic():
                if tx_info[0] is not None and tx_info[1] >= in_tx.block_height + ETH_TX__BLOCKS_CONFIRM_NUM:
                    in_tx.status = TransactionStatus.confirmed
                    # check that absolute difference of incoming tx value and application value is not greater then
                    # backend setting (LOGIC__MAX_DIFF_PERCENT)
                    if math.calc_absolute_difference(in_tx.value,
                                                     in_tx.application.base_amount) > LOGIC__MAX_DIFF_PERCENT:
                        in_tx.application.status = str(ApplicationStatus.confirming)
                    # check that incoming tx value is not greater then currency balance (reversed exchange operation)
                    elif in_tx.application.is_reverse and \
                            in_tx.application.currency_pair.base_currency.balance < in_tx.value:
                        in_tx.application.status = str(ApplicationStatus.refunding)
                        in_tx.status = TransactionStatus.rejected
                    #check that incoming tx value is not greater then currency balance (nonreversed exchange operation)
                    elif not in_tx.application.is_reverse and \
                            in_tx.application.currency_pair.reciprocal_currency.balance < in_tx.value:
                        in_tx.application.status = str(ApplicationStatus.refunding)
                        in_tx.status = TransactionStatus.rejected
                    else:
                        in_tx.application.status = str(ApplicationStatus.converting)
                    #check that incoming tx value is not over-limit
                    if not math.check_amount_limit(in_tx.value,
                                                   in_tx.application.currency_pair,
                                                   in_tx.application.is_reverse,
                                                   True):
                        in_tx.application.status = str(ApplicationStatus.refunding)
                        in_tx.status = TransactionStatus.rejected
                elif tx_info[0] is None:
                    in_tx.application_id = None
                    in_tx.status = TransactionStatus.rejected
                in_tx.application.save()
                in_tx.save()
        except:
            exception_str = ''.join(traceback.format_exception(*sys.exc_info()))
            logging.getLogger(__name__).error("Failed to process incoming tx \"{}\" due to error:\n{}"
                                                .format(in_tx.transaction_id, exception_str))

        logger.info('Finished process linked unconfirmed events')


def fetch_eth_events():
    logger.info('Run fetch eth events')

    replenisher_entries = Replenisher.objects.filter(is_removed=False)
    replenishers = [replenisher.address.lower() for replenisher in replenisher_entries]

    currencies = Currency.objects.all()
    for currency in currencies:
        if len(replenishers) == 0:
            break

        try:
            last_event = IncomingTransaction.objects.latest('block_height')
            last_block = last_event.block_height + 1
        except IncomingTransaction.DoesNotExist:
            last_block = 0

        events = eth_events.get_incoming_txs(currency.view_address if currency.is_erc20_token else currency.exchanger_address,
                                             currency.exchanger_address,
                                             currency.abi,
                                                'Transfer' if currency.is_erc20_token else 'ReceiveEvent',
                                             last_block)
        try:
            with transaction.atomic():
                for evnt in events:
                    try:
                        event_application = Application.objects.annotate(in_tx_cnt=Count('incoming_txs'))\
                            .filter(Q(is_active=True) &
                                    Q(address__address__iexact=evnt[4]) &
                                    Q(in_tx_cnt=0) &
                                    Q(created_at__lt=evnt[2]) &
                                    Q(expired_at__gte=evnt[2])) \
                            .latest('created_at')
                        application_id = event_application.pk
                    except Application.DoesNotExist:
                        application_id = None

                    if not evnt[4].lower() in replenishers:
                        in_tx = IncomingTransaction.objects.create(transaction_id=evnt[0],
                                                                   currency_id=currency.pk,
                                                                   application_id=application_id,
                                                                   is_linked=True if application_id else False,
                                                                   block_height=evnt[1],
                                                                   mined_at=str(evnt[2]),
                                                                   from_address=evnt[4],
                                                                   to_address=evnt[5],
                                                                   value=evnt[6],
                                                                   status=TransactionStatus.not_confirmed)
                        in_tx.save()
                        if application_id:
                            event_application.status = str(ApplicationStatus.waiting)
                            event_application.save()
        except:
            exception_str = ''.join(traceback.format_exception(*sys.exc_info()))
            logging.getLogger(__name__).error("Failed to fetch eth events \"{}\" due to error:\n{}"
                                                .format(currency.symbol, exception_str))

    logger.info('Finished fetch eth events')


def process_applications():
    logger.info('Run process applications')

    applications = Application.objects.filter( Q(status=str(ApplicationStatus.created)) |
                                               Q(status=str(ApplicationStatus.refunding)) |
                                               Q(status=str(ApplicationStatus.converting)) |
                                              (Q(status=str(ApplicationStatus.confirming)) &
                                               Q(expired_at__lt=datetime.now(tzlocal()))))

    for application in applications:
        try:
            if application.refundes.count() > 0 or \
               application.exchanges.count() > 0:
                continue

            with transaction.atomic():
                if application.status == str(ApplicationStatus.confirming):
                    if datetime.now(tzlocal()) > application.expired_at:
                        application.status = str(ApplicationStatus.refunding)
                        application.is_active = False
                        application.save()
                elif application.status == str(ApplicationStatus.refunding):
                    in_tx = application.incoming_txs.first()
                    refund_value = in_tx.value - get_borrow_fee(in_tx.value)
                    if refund_value < 0:
                        logger.error('outgoing tx value < 0')
                    if in_tx is not None:
                        refund = Refund.objects.create(application_id=application.pk,
                                                       incoming_transaction_id=in_tx.pk,
                                                       currency_id=utils.get_refund_currency_by_application(application),
                                                       to_address=application.address.address,
                                                       created_at=datetime.now(tzlocal()),
                                                       value=refund_value,
                                                       status=TransactionStatus.confirmed)
                        refund.save()
                        logger.info('create refund tx for app {}'.format(application.pk))
                elif application.status == str(ApplicationStatus.converting):
                    in_tx = application.incoming_txs.first()
                    if in_tx is not None:
                        exchange = Exchange.objects \
                            .create(application_id=application.pk,
                                    incoming_transaction_id=in_tx.pk,
                                    currency_id=utils.get_exchange_currency_by_application(application),
                                    to_address=application.address.address,
                                    created_at=datetime.now(tzlocal()),
                                    value=math.round_amount(math.calc_reciprocal_amount(in_tx.value, application.rate),
                                                            application.currency_pair,
                                                            application.is_reverse,
                                                            False),
                                    status=TransactionStatus.confirmed)
                        exchange.save()
                        logger.info('create exchange tx for app {}'.format(application.pk))
                elif application.status == str(ApplicationStatus.created) and \
                        application.expired_at < datetime.now(tzlocal()) and \
                        application.is_active:
                    application.status = str(ApplicationStatus.cancelled)
                    application.save()
                    logger.info('cancel application {}'.format(application.pk))

        except:
            exception_str = ''.join(traceback.format_exception(*sys.exc_info()))
            logging.getLogger(__name__).error("Failed to process application \"{}\" due to error:\n{}"
                                                .format(application.pk, exception_str))

    logger.info('Finished process applications')


def process_license_users_addresses():
    # noinspection PyBroadException
    try:
        logger.info('Start to process license users addresses')

        addresses = Address.objects.filter(Q(is_verified=True) &
                                           Q(is_allowed=False)) \
                                   .order_by('id')  # type: List[Address]

        currencies = Currency.objects.filter(is_erc20_token=True)

        for address in addresses:
            try:
                with transaction.atomic():
                    for currency in currencies:
                        if currency.license_registry_address is not None:
                            expiration_time = round(time.time()) + (365 * 24 * 60 * 60)
                            eth_contracts.licenseUser(currency.license_registry_address, address.address, expiration_time)
                    address.is_allowed = True
                    address.save()
                    logger.info('address {} licensed successfully'.format(address.address))
            except Exception:
                exception_str = ''.join(traceback.format_exception(*sys.exc_info()))
                logging.getLogger(__name__).error(
                    "Failed license address {} due to exception:\n{}".format(address.address, exception_str))

        logger.info('Finished process license users addresses')
    except Exception:
        exception_str = ''.join(traceback.format_exception(*sys.exc_info()))
        logging.getLogger(__name__).error("Failed to process license users addresses due to exception:\n{}"
                                          .format(exception_str))


def get_currency_contract_params(currency, is_refund = False):
    contract_address = currency.exchanger_address
    token_address = currency.view_address if currency.is_erc20_token else ''
    fn = None
    if is_refund and not currency.is_erc20_token:
        fn = celery_refund_eth
    elif is_refund and currency.is_erc20_token:
        fn = celery_refund_token
    if not is_refund and not currency.is_erc20_token:
        fn = celery_transfer_eth
    if not is_refund and currency.is_erc20_token:
        fn = celery_transfer_token

    abi = currency.abi

    return abi, contract_address, token_address, fn


def get_reciprocal_currency_by_application(application):
    if application.is_reverse:
        return application.currency_pair.base_currency
    else:
        return application.currency_pair.reciprocal_currency


def get_transaction_params(tx, is_refund = False):
    return get_currency_contract_params(tx.currency, is_refund) if is_refund else \
        get_currency_contract_params(get_reciprocal_currency_by_application(tx.application), is_refund)


def process_outgoing_transactions(txs, start_nonce, is_refund = False):
    nonce = start_nonce
    for tx in txs:
        try:
            abi, contract_address, token_address, celery_fn = get_transaction_params(tx, is_refund)

            celery_fn(tx.pk, abi, contract_address, tx.incoming_transaction.transaction_id,
                      token_address, tx.to_address, tx.value, nonce, is_refund)
            nonce+=1
        except Exception:
            exception_str = ''.join(traceback.format_exception(*sys.exc_info()))
            logging.getLogger(__name__).error(
                "Failed to process outgoing transaction {} is_refund:{} due to exception:\n{}".format(tx.pk,
                                                                                                      is_refund,
                                                                                                      exception_str))


def process_outgoing_transactions_runner():
    # noinspection PyBroadException
    try:
        logger.info('Start to process outgoing transactions')

        pending_exchanges = Exchange.objects.filter(Q(status=TransactionStatus.pending) &
                                                    ~Q(transaction_id="")) \
                                            .order_by('id')  # type: List[Exchange]
        pending_refundes = Refund.objects.filter(Q(status=TransactionStatus.pending) &
                                                 ~Q(transaction_id="")) \
                                         .order_by('id')  # type: List[Refund]

        overall_limit_count = ETH_TX__MAX_PENDING_TX_COUNT - pending_exchanges.count() - pending_refundes.count()
        if overall_limit_count <= 0:
            logger.info('Finished to process new outgoing transactions. Over the limit.')
            return

        exchange_limit_count = int(overall_limit_count * 2 / 3)
        refund_limit_count = overall_limit_count - exchange_limit_count

        if exchange_limit_count <= 0:
            logger.info('Finished to process new exchange transactions. Over the limit.')
            return

        exchanges = Exchange.objects.filter(Q(status=TransactionStatus.confirmed) &
                                            (Q(transaction_id="") | Q(transaction_id=None))) \
                                    .order_by('id')[:exchange_limit_count]  # type: List[Exchange]
        if exchanges.count() > 0:
            nonce = eth_utils.get_exchanger_nonce()
            process_outgoing_transactions(exchanges, nonce)

        if refund_limit_count <= 0:
            logger.info('Finished to process new refund transactions. Over the limit.')
            return

        refunds = Refund.objects.filter(Q(status=TransactionStatus.confirmed) &
                                            (Q(transaction_id="") | Q(transaction_id=None))) \
                                    .order_by('id')[:exchange_limit_count]  # type: List[Refund]
        if refunds.count() > 0:
            nonce = eth_utils.get_exchanger_nonce()
            process_outgoing_transactions(refunds, nonce, True)

        logger.info('Finished process outgoing transactions')
    except Exception:
        exception_str = ''.join(traceback.format_exception(*sys.exc_info()))
        logging.getLogger(__name__).error("Failed to process withdraws due to exception:\n{}"
                                          .format(exception_str))


def check_outgoing_transactions(txs, is_refund = False):
    for tx in txs:
        tx_info, block_number = eth_events.get_tx_info(tx.transaction_id)

        if tx_info is not None:
            with transaction.atomic():
                if tx_info.status == 1:
                    tx.status = TransactionStatus.success
                    if tx.application is not None:
                        if is_refund:
                            tx.application.status = str(ApplicationStatus.refunded)
                        else:
                            tx.application.status = str(ApplicationStatus.converted)
                            ga_integration.on_exchange_completed(tx.application)
                        tx.application.save()
                elif tx_info.status == 0:
                    tx.status = TransactionStatus.fail
                    logger.info('outgoing transaction {} (is_refund: {}) failed'
                                .format(tx.transaction_id, is_refund))
                tx.save()


def check_outgoing_transactions_runner():
    # noinspection PyBroadException
    try:
        logging.getLogger(__name__).info("Start to check outgoing transactions")

        exchanges = Exchange.objects.filter( Q(status=TransactionStatus.pending) &
                                             ~Q(transaction_id="") ) \
                                    .order_by('id')  # type: List[Exchange]
        refunds = Refund.objects.filter(Q(status=TransactionStatus.pending) &
                                        ~Q(transaction_id="")) \
                                 .order_by('id')  # type: List[Exchange]

        check_outgoing_transactions(exchanges)
        check_outgoing_transactions(refunds, True)

        logging.getLogger(__name__).info("Finished checking outgoing transactions")
    except Exception:
        exception_str = ''.join(traceback.format_exception(*sys.exc_info()))
        logging.getLogger(__name__).error("Failed to check outgoing transactions due to exception:\n{}"
                                          .format(exception_str))


def fetch_replenisher():
    # noinspection PyBroadException
    try:
        logging.getLogger(__name__).info("Start to fetch replenishers")

        eth_currency = Currency.objects.get(symbol__icontains='eth')
        try:
            last_event = Replenisher.objects.latest('block_height')
            last_block = last_event.block_height + 1
        except Replenisher.DoesNotExist:
            last_block = 0

        events = eth_events.get_replenishers(eth_currency.exchanger_address, eth_currency.abi, last_block)
        with transaction.atomic():
            for evnt in events:
                tx_hash, block_height, mined_at, evnt_type, evnt_address = evnt

                if evnt_type == "ReplenisherDisabledEvent":
                    try:
                        replenisher = Replenisher.objects.filter(address__iexact=evnt_address).latest('block_height')
                        replenisher.is_removed = True
                        replenisher.last_updated_at = timezone.now()
                        replenisher.save()
                    except Replenisher.DoesNotExist:
                        pass
                else:
                    replenisher = Replenisher.objects.create(transaction_id=tx_hash,
                                                   block_height=block_height,
                                                   mined_at=str(mined_at),
                                                   type=evnt_type,
                                                   address=evnt_address)
                    replenisher.save()

        logging.getLogger(__name__).info("Finished fetching replenishers")
    except Exception:
        exception_str = ''.join(traceback.format_exception(*sys.exc_info()))
        logging.getLogger(__name__).error("Failed to fetch replenishers due to exception:\n{}"
                                          .format(exception_str))
