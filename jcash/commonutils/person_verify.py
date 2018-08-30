from __future__ import print_function
import time
import onfido
from onfido.rest import ApiException
from pprint import pprint
import requests

from django.conf import settings

from jcash.api.models import DocumentVerification


STATUS_COMPLETE = 'complete'
STATUS_IN_PROGRESS = 'in progress'
RESULT_CLEAR = 'clear'
RESULT_CONSIDER = 'consider'


def get_client(api_key=None):
    api_key = api_key or settings.ONFIDO_API_KEY
    onfido.configuration.api_key['Authorization'] = 'token=' + api_key
    onfido.configuration.api_key_prefix['Authorization'] = 'Token'
    # create an instance of the API class
    api = onfido.DefaultApi()
    return api


def create_applicant(first_name, middle_name, last_name, email, birthday):
    details = {
        'first_name': first_name,
        'last_name': last_name,
        'middle_name': middle_name,
        'email': email,
        'dob': birthday,
    }
    applicant = onfido.Applicant(**details)

    api = get_client()
    resp = api.create_applicant(data=applicant)
    return resp.id


def create_check(applicant_id):

    reports = [
        onfido.Report(name='document'),
        onfido.Report(name='watchlist', variant='full'),
    ]

    check = onfido.CheckCreationRequest(
        type='express',
        reports=reports
    )

    api = get_client()
    resp = api.create_check(applicant_id, data=check)
    return resp.id


def upload_document(applicant_id, document_path, document_ext, document_type):
    api = get_client()

    document_ext = document_ext.lower()

    if document_ext == 'jpeg':
        document_ext = 'jpg'

    if document_ext not in ('jpg', 'png', 'pdf'):
        raise RuntimeError(
            'Document extension {} is not allowed. Path {}, applicant {}, type {}'.format(
                document_ext, document_path, applicant_id, document_type))

    if document_type not in ('selfie', 'passport', 'utilitybills'):
        raise RuntimeError(
            'Document type {} is not allowed. Path {}, applicant {}, type {}'.format(
                document_ext, document_path, applicant_id, document_type))

    resp = None
    if document_type == 'selfie':
        resp = api.upload_live_photo(applicant_id, file=document_path, advanced_validation=True)
    elif document_type == 'passport':
        resp = api.upload_document(applicant_id, file=document_path, type='passport')
    elif document_type == 'utilitybills':
        resp = api.upload_document(applicant_id, file=document_path, type='bank_statement')

    return resp.id
