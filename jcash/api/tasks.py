from jcash.commonutils.app_init import initialize_app
from jcash.commonutils.celery_lock import locked_task
from jcash.celeryapp import celery_app
from jcash.commonutils.eth_contracts import transferEth, transferToken, refundEth, refundToken


@celery_app.task()
@initialize_app
@locked_task('to_address')
def celery_transfer_eth(tx_pk: int,
                    contract_abi: str,
                    contract_address: str,
                    to_address: str,
                    value: float,
                    nonce: int,
                    is_refund=False) -> str:
    transferEth(tx_pk, contract_abi, contract_address, to_address, value, nonce, is_refund)


@celery_app.task()
@initialize_app
@locked_task('to_address')
def celery_transfer_token(tx_pk: int,
                    contract_abi: str,
                    contract_address: str,
                    to_address: str,
                    value: float,
                    nonce: int,
                    is_refund=False) -> str:
    transferToken(tx_pk, contract_abi, contract_address, to_address, value, nonce, is_refund)


@celery_app.task()
@initialize_app
@locked_task('to_address')
def celery_refund_eth(tx_pk: int,
                  contract_abi: str,
                  contract_address: str,
                  to_address: str,
                  value: float,
                  nonce: int,
                  is_refund=True) -> str:
    refundEth(tx_pk, contract_abi, contract_address, to_address, value, nonce, is_refund)


@celery_app.task()
@initialize_app
@locked_task('to_address')
def celery_refund_token(tx_pk: int,
                  contract_abi: str,
                  contract_address: str,
                  to_address: str,
                  value: float,
                  nonce: int,
                  is_refund=True) -> str:
    refundToken(tx_pk, contract_abi, contract_address, to_address, value, nonce, is_refund)
