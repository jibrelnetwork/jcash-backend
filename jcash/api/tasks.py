from jcash.commonutils.app_init import initialize_app
from jcash.commonutils.celery_lock import locked_task
from jcash.celeryapp import celery_app
from jcash.commonutils.eth_contracts import transfer, refund


@celery_app.task()
@initialize_app
@locked_task('to_address')
def celery_transfer(tx_pk: int,
                    contract_abi: str,
                    contract_address: str,
                    to_address: str,
                    value: float,
                    nonce: int,
                    is_refund=False) -> str:
    transfer(tx_pk, contract_abi, contract_address, to_address, value, nonce, is_refund)


@celery_app.task()
@initialize_app
@locked_task('to_address')
def celery_refund(tx_pk: int,
                  contract_abi: str,
                  contract_address: str,
                  to_address: str,
                  value: float,
                  nonce: int,
                  is_refund=True) -> str:
    refund(tx_pk, contract_abi, contract_address, to_address, value, nonce, is_refund)
