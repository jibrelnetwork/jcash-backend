from __future__ import print_function
import time
import onfido
from onfido.rest import ApiException
from pprint import pprint
import requests
import tempfile

from django.conf import settings
from django.contrib.auth import get_user_model


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


def create_applicant(user_id):
    user = get_user_model().objects.get(pk=user_id)

    details = {
        'first_name': user.account.first_name,
        'last_name': user.account.last_name,
        'email': user.email,
        'dob': user.account.birthday,
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


def upload_document(applicant_id, document_url, document_type):
    api = get_client()
    resp = requests.get(document_url)
    if not document_type:
        document_type = resp.headers['X-File-Name'].split('.')[-1]
    if document_type == 'jpeg':
        document_type = 'jpg'

    document_type = document_type.lower()
    if document_type not in ('jpg', 'png', 'pdf'):
        raise RuntimeError(
            'Document type {} is not allowed. Url {}, applicant {}'.format(
                document_type, document_url, applicant_id))

    if resp.status_code != 200:
        raise RuntimeError("Can't get document file {} for applicant {}".format(
                           document_url, applicant_id))
    with tempfile.NamedTemporaryFile(suffix='.' + document_type) as fp:
        fp.write(resp.content)
        resp = api.upload_document(applicant_id, file=fp.name, type='passport')
        return resp.id
