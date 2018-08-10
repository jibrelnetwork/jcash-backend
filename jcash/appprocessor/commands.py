import logging
import sys
import traceback
from datetime import datetime, timedelta
from dateutil.tz import tzlocal
import time

from django.db import transaction
from django.db.models import Q, F, Count, Max
from django.utils import timezone
from django.core.files import File
from django.core.files.temp import NamedTemporaryFile
import requests

from jcash.api.models import (
    Document,
    DocumentType,
    DocumentHelper,
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
    DocumentVerificationStatus,
    LicenseAddress,
    LicenseAddressStatus,
    Personal,
    Corporate,
    ApplicationCancelReason,
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
    sql_utils,
)
from jcash.api.tasks import celery_refund_eth, celery_transfer_eth, celery_refund_token, celery_transfer_token
from jcash.settings import (
    LOGIC__MAX_VERIFICATION_ATTEMPTS,
    ETH_TX__BLOCKS_CONFIRM_NUM,
    LOGIC__MAX_DIFF_PERCENT,
    LOGIC__EXPIRATION_LIMIT_SEC,
    LOGIC__REFUND_FEE_PERCENT,
    ETH_TX__MAX_PENDING_TX_COUNT,
    ONFIDO_API_KEY,
)


logger = logging.getLogger(__name__)


def process_all_notifications_runner():
    logger.info('Run notifications processing')

    notifications_to_send = Notification.objects.filter(Q(is_sended=False) & ~Q(meta__has_key='message_id')).all()
    for notification in notifications_to_send:
        success, provider, message_id = notify.send_notification(notification.pk)
        notification.is_sended = success
        notification.meta['message_id'] = message_id
        notification.meta['provider'] = provider

        notification.save()

    logger.info('Finished notifications processing')


def get_customer_by_document_verification(document_verification: DocumentVerification):
    """
    Get verification's customer
    :param document_verification: DocumentVerification
    :return: customer
    """
    if document_verification and document_verification.personal:
        return document_verification.personal
    if document_verification and document_verification.corporate:
        return document_verification.corporate
    return None


def download_onfido_report(document_verification, url):
    """
    Save onfido report into DB
    """
    r = requests.get(url, headers = {'Authorization': 'Token token={}'.format(ONFIDO_API_KEY)})

    if r.status_code == 200:
        tmp_file = NamedTemporaryFile(delete=True)
        tmp_file.write(r.content)
        tmp_file.flush()

        try:
            if not document_verification.report:
                document_verification.report = Document.objects.create(user=document_verification.user,
                                                                       type=DocumentType.report,
                                                                       ext='html')

                document_verification.report.image.save(DocumentHelper.unique_document_filename(None, 'report.html'),
                                                        File(tmp_file))
        except:
            logger.error('download_onfido_report: failed saving report into DB (verification:{})'
                         .format(document_verification.pk))
    else:
        logger.info('download_onfido_report: failed downloading report from {}'.format(url))


def check_document_verification_status(document_verification_id):
    """
    Check and store OnFido check status and result
    """
    document_verification = DocumentVerification.objects.get(pk=document_verification_id)
    logger.info('Checking verification status for verification_id=%s', document_verification_id)
    if document_verification.onfido_check_status == person_verify.STATUS_COMPLETE:
        logger.warn('Document verification completed for %s', document_verification_id)
        return
    api = person_verify.get_client()

    customer = get_customer_by_document_verification(document_verification)
    if document_verification and customer:
        with transaction.atomic():
            check = api.find_check(customer.onfido_applicant_id, document_verification.onfido_check_id)
            logger.info('Document verification status is: %s, result: %s', check.status, check.result)
            document_verification.onfido_check_status = check.status
            document_verification.onfido_check_result = check.result
            if check.download_uri:
                download_onfido_report(document_verification, check.download_uri)
            document_verification.save()


def check_document_verification_status_runner():
    logger.info('Run check verification status')

    doc_verifications = DocumentVerification.objects \
        .filter(onfido_check_result=None) \
        .exclude(onfido_check_id=None) \
        .all()
    for doc in doc_verifications:
        with transaction.atomic():
            logger.info('Run check verification status for document_verification id=%s', doc.pk)
            check_document_verification_status(doc.pk)

    logger.info('Finished checking verification status')


def upload_document(document, user_name, onfido_applicant_id):
    """
    Upload document to onfido
    """
    if not document.onfido_document_id:
        try:
            document_id = person_verify.upload_document(onfido_applicant_id,
                                                        document.image.path,
                                                        document.ext,
                                                        document.type)
        except:
            exception_str = ''.join(traceback.format_exception(*sys.exc_info()))
            logging.getLogger(__name__).info(
                "Failed to upload document aplic_id:{} doc_id:{} doc_type:{} onto onfido  due to error:\n{}"
                    .format(onfido_applicant_id, document.pk, document.type, exception_str)
            )
        else:
            document.onfido_document_id = document_id
            document.save()
            logger.info('Document for %s type: %s uploaded: %s', user_name, document.type, document_id)
    else:
        logger.info('Document for %s type: %s already uploaded: %s', user_name, document.type, document.onfido_document_id)


def verify_document(document_verification_id):
    """
    Create OnFido check to verify customer's documents
    """
    with transaction.atomic():
        now = timezone.now()
        document_verification = DocumentVerification.objects.select_for_update().get(id=document_verification_id)

        if document_verification.onfido_check_status == person_verify.STATUS_COMPLETE:
            logger.warn('Verification completed for id %s, exiting', document_verification.pk)
            return

        if document_verification.onfido_check_id is not None:
            logger.warn('Check exists for id %s, exiting', document_verification.pk)
            return

        if (document_verification.verification_started_at and
            (now - document_verification.verification_started_at) < timedelta(minutes=5)):
            logger.info('Verification already started for id %s, exiting', document_verification.pk)
            return

        logger.info('Start verifying process for id %s', document_verification.pk)
        document_verification.verification_started_at = now
        document_verification.verification_attempts += 1
        document_verification.save()

    customer = get_customer_by_document_verification(document_verification)
    if document_verification and customer:
        with transaction.atomic():
            if not customer.onfido_applicant_id:
                if isinstance(customer, Personal):
                    full_name = document_verification.personal.fullname
                    first_name = full_name.split(" ")[0]
                    last_name = full_name.split(" ")[1] if len(full_name.split(" "))>1 else ""
                    birtday = document_verification.personal.birthday
                elif isinstance(customer, Corporate):
                    full_name = document_verification.corporate.contact_fullname
                    first_name = full_name.split(" ")[0]
                    last_name = full_name.split(" ")[1] if len(full_name.split(" "))>1 else ""
                    birtday = document_verification.corporate.contact_birthday
                else:
                    logger.error('Document verification id=%s has no customer', document_verification.pk)
                    return

                email = document_verification.user.email
                if not customer.onfido_applicant_id or document_verification.is_applicant_changed:
                    try:
                        applicant_id = person_verify.create_applicant(first_name, last_name, email, birtday)
                    except:
                        exception_str = ''.join(traceback.format_exception(*sys.exc_info()))
                        logging.getLogger(__name__).info("Failed to create onfido applicant {}{}{}{} due to error:\n{}"
                                                          .format(first_name, last_name, email, birtday, exception_str))
                    else:
                        customer.onfido_applicant_id = applicant_id
                        customer.save()

                logger.info('Applicant %s created for %s',
                            customer.onfido_applicant_id,
                            document_verification.user.username)
            else:
                logger.info('Applicant for %s already exists: %s', document_verification.user.username,
                            customer.onfido_applicant_id)

            try:
                upload_document(document_verification.passport,
                                document_verification.user.username,
                                customer.onfido_applicant_id)
                upload_document(document_verification.utilitybills,
                                document_verification.user.username,
                                customer.onfido_applicant_id)
                upload_document(document_verification.selfie,
                                document_verification.user.username,
                                customer.onfido_applicant_id)
            except:
                document_verification.status = DocumentVerificationStatus.upload_issue
                document_verification.save()
                exception_str = ''.join(traceback.format_exception(*sys.exc_info()))
                logger.error('Check for {} verification {} failed due to error:\n{}'.format(
                    document_verification.user.username,
                    document_verification.pk,
                    exception_str
                ))
            else:
                check_id = person_verify.create_check(customer.onfido_applicant_id)
                document_verification.onfido_check_id = check_id
                document_verification.onfido_check_created = timezone.now()
                document_verification.status = DocumentVerificationStatus.submitted
                document_verification.save()
                logger.info('Check for %s created: %s',
                            document_verification.user.username,
                            document_verification.onfido_check_id)


def process_all_uncomplete_verifications():
    logger.info('Run process uncomplete verifications')

    now = datetime.now()
    condition = (
        Q(onfido_check_id=None) &
        Q(verification_attempts__lt=LOGIC__MAX_VERIFICATION_ATTEMPTS) &
        (Q(verification_started_at__lt=(now - timedelta(minutes=5))) |
         Q(verification_started_at=None))
    )
    documents_verifications = DocumentVerification.objects.filter(condition).all()
    for doc_verification in documents_verifications:
        logger.info('Retry uncomplete document verification %s', doc_verification.pk)
        verify_document(doc_verification.pk)

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
                    # check that incoming tx value is not greater then currency balance (reversed exchange operation)
                    if in_tx.application.is_reverse and \
                        utils.get_currency_balance(in_tx.application.currency_pair.base_currency) < \
                            math.calc_reciprocal_amount(in_tx.value, in_tx.application.rate):
                        in_tx.application.status = str(ApplicationStatus.refunding)
                        in_tx.application.reason = str(ApplicationCancelReason.cancelled_by_currency_balance)
                        in_tx.status = TransactionStatus.rejected
                    #check that incoming tx value is not greater then currency balance (nonreversed exchange operation)
                    elif not in_tx.application.is_reverse and \
                        utils.get_currency_balance(in_tx.application.currency_pair.reciprocal_currency) < \
                            math.calc_reciprocal_amount(in_tx.value, in_tx.application.rate):
                        in_tx.application.status = str(ApplicationStatus.refunding)
                        in_tx.application.reason = str(ApplicationCancelReason.cancelled_by_currency_balance)
                        in_tx.status = TransactionStatus.rejected
                    # check that absolute difference of incoming tx value and application value is not greater then
                    # backend setting (LOGIC__MAX_DIFF_PERCENT)
                    elif math.calc_absolute_difference(in_tx.value,
                                                       in_tx.application.base_amount) > LOGIC__MAX_DIFF_PERCENT:
                        in_tx.application.status = str(ApplicationStatus.confirming)
                    else:
                        in_tx.application.status = str(ApplicationStatus.converting)
                    #check that incoming tx value is not over-limit
                    if not math.check_amount_limit(in_tx.value,
                                                   in_tx.application.currency_pair,
                                                   in_tx.application.is_reverse,
                                                   True):
                        in_tx.application.status = str(ApplicationStatus.refunding)
                        in_tx.application.reason = str(ApplicationCancelReason.cancelled_by_currency_limits)
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
                                                'Transfer' if currency.is_erc20_token else 'ReceiveEthEvent',
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
                        event_application = None
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
                            event_application.base_amount_actual = evnt[6]
                            event_application.reciprocal_amount_actual = math.round_amount(
                                math.calc_reciprocal_amount(float(evnt[6]), event_application.rate),
                                event_application.currency_pair,
                                event_application.is_reverse,
                                False)
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
                        application.reason = str(ApplicationCancelReason.cancelled_by_timeout)
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
                    application.reason = str(ApplicationCancelReason.cancelled_by_timeout)
                    application.save()
                    notify.send_email_exchange_unsuccessful(
                        application.user.email,
                        notify._format_fiat_value(application.base_amount_actual,
                                                  application.base_currency),
                        ApplicationCancelReason.__dict__[application.reason].description \
                            if application.reason in ApplicationCancelReason.__dict__ \
                            else "An unexpected error occured",
                        user_id=application.user.pk)
                    logger.info('cancel application {}'.format(application.pk))

        except:
            exception_str = ''.join(traceback.format_exception(*sys.exc_info()))
            logging.getLogger(__name__).error("Failed to process application \"{}\" due to error:\n{}"
                                                .format(application.pk, exception_str))

    logger.info('Finished process applications')


def fetch_currencies_state():
    # noinspection PyBroadException
    try:
        logging.getLogger(__name__).info("Start to fetch currencies state")

        currencies = Currency.objects.filter(is_disabled=False)

        for currency in currencies:
            with transaction.atomic():
                if currency.is_erc20_token:
                    currency.balance = eth_contracts.balanceToken(currency.abi,
                                                                  currency.view_address,
                                                                  currency.exchanger_address)
                else:
                    currency.balance = eth_contracts.balanceEth(currency.exchanger_address)
                currency.save()
                logging.getLogger(__name__).info("Currency balance is {}".format(currency.balance))

        logging.getLogger(__name__).info("Finished fetching currencies state")
    except Exception:
        exception_str = ''.join(traceback.format_exception(*sys.exc_info()))
        logging.getLogger(__name__).error("Failed to fetch currencies state due to exception:\n{}"
                                          .format(exception_str))


def process_license_users_addresses():
    # noinspection PyBroadException
    try:
        logger.info('Start to process license users addresses')
        license_limit_count = 1
        license_addresses = LicenseAddress.objects.filter(Q(status=LicenseAddressStatus.created)).order_by(
            'id'
        )[:license_limit_count]  # type: List[LicenseAddress]

        for la in license_addresses:
            # noinspection PyBroadException
            try:
                with transaction.atomic():
                    la.status = LicenseAddressStatus.pending
                    la.save()

                expiration_time = round(time.time()) + (365 * 24 * 60 * 60)
                txs_data = eth_contracts.licenseUser(la.currency.license_registry_address,
                                                     la.address.address,
                                                     la.is_remove_license,
                                                     expiration_time)
                with transaction.atomic():
                    la.status = LicenseAddressStatus.success
                    for key in txs_data:
                        la.meta[key] = txs_data[key]
                    la.save()
                    logger.info('address: {} currency: {} licensed successfully'.format(la.address.address,
                                                                                        la.currency.display_name))
            except Exception:
                exception_str = ''.join(traceback.format_exception(*sys.exc_info()))
                logging.getLogger(__name__).error(
                    "Failed license address: {} currency: {} due to exception:\n{}".format(la.address.address,
                                                                                           la.currency.display_name,
                                                                                           exception_str))

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

        # JCASH-100 Disable automatic refunds for unknown incoming transactions
        refunds = Refund.objects.filter(Q(status=TransactionStatus.confirmed) &
        #                               Q(is_admin_approved=True) &
                                        ~Q(application_id=None) &
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
                            notify.send_email_refund_successful(
                                tx.application.user.email,
                                notify._format_fiat_value(tx.application.base_amount_actual,
                                                          tx.application.base_currency),
                                tx.application.address.address,
                                ApplicationCancelReason.__dict__[tx.application.reason].description \
                                    if tx.application.reason in ApplicationCancelReason.__dict__ \
                                    else "An unexpected error occured",
                                user_id=tx.application.user.pk)
                        else:
                            tx.application.status = str(ApplicationStatus.converted)
                            ga_integration.on_exchange_completed(tx.application)
                            notify.send_email_exchange_successful(
                                tx.application.user.email,
                                notify._format_fiat_value(tx.application.base_amount_actual,
                                                          tx.application.base_currency),
                                notify._format_fiat_value(tx.application.reciprocal_amount_actual,
                                                          tx.application.reciprocal_currency),
                                tx.application.address.address,
                                notify._format_conversion_rate(
                                    tx.application.rate if not tx.application.is_reverse else \
                                        1.0 / tx.application.rate,
                                    'ETH',
                                    tx.application.base_currency if tx.application.is_reverse else \
                                        tx.application.reciprocal_currency),
                                user_id=tx.application.user.pk)
                        tx.application.save()
                elif tx_info.status == 0:
                    tx.status = TransactionStatus.fail
                    if tx.application is not None:
                        tx.application.status = str(ApplicationStatus.cancelled)
                        tx.application.reason = str(ApplicationCancelReason.cancelled_by_contract)
                        tx.application.save()
                        notify.send_email_exchange_unsuccessful(
                                tx.application.user.email,
                                notify._format_fiat_value(tx.application.base_amount_actual,
                                                          tx.application.base_currency),
                                ApplicationCancelReason.__dict__[tx.application.reason].description \
                                    if tx.application.reason in ApplicationCancelReason.__dict__ \
                                    else "An unexpected error occured",
                                user_id=tx.application.user.pk)
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

        try:
            eth_currency = Currency.objects.get(Q(symbol__icontains='eth') &
                                                ~Q(is_disabled=True))
            try:
                last_event = Replenisher.objects.latest('block_height')
                last_block = last_event.block_height + 1
            except Replenisher.DoesNotExist:
                last_block = 0

            events = eth_events.get_replenishers(eth_currency.exchanger_address, eth_currency.abi, last_block)
            with transaction.atomic():
                for evnt in events:
                    tx_hash, block_height, mined_at, evnt_type, evnt_address = evnt

                    if evnt_type == "ManagerPermissionRevokedEvent":
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

        except Currency.DoesNotExist:
            logging.getLogger(__name__).warn("Currencies not configured")

        logging.getLogger(__name__).info("Finished fetching replenishers")
    except Exception:
        exception_str = ''.join(traceback.format_exception(*sys.exc_info()))
        logging.getLogger(__name__).error("Failed to fetch replenishers due to exception:\n{}"
                                          .format(exception_str))


def license_address(address_id: int, currency_id: int, is_removed: bool):
    logging.getLogger(__name__).info(
        "Create LicenseAddress entry for address_id: {} currency_id: {} is_remove_license: {}" \
            .format(address_id, currency_id, is_removed))
    LicenseAddress.objects.create(address_id=address_id, currency_id=currency_id, is_remove_license=is_removed)


def check_address_licenses():
    # noinspection PyBroadException
    try:
        logging.getLogger(__name__).info("Start to check users licenses")

        addresses = Address.objects.raw(sql_utils.generate_query_check_address_licenses())

        with transaction.atomic():
            for address in addresses:
                license_address(address.pk, address.currency_id, address.is_removed)

        logging.getLogger(__name__).info("Finished checking address licenses")
    except Exception:
        exception_str = ''.join(traceback.format_exception(*sys.exc_info()))
        logging.getLogger(__name__).error("Failed to check address licenses due to exception:\n{}"
                                          .format(exception_str))
