from datetime import datetime
import logging

import django.db.backends.utils
from django.contrib.postgres.fields.jsonb import JsonAdapter


from .celeryapp import celery_app


__all__ = ['celery_app']

original_execute = django.db.backends.utils.CursorWrapper.execute
original_executemany = django.db.backends.utils.CursorWrapper.executemany

logger = logging.getLogger('django.db.backends')


class _FormatConverter(object):

    def __init__(self, param_mapping):
        self.param_mapping = param_mapping
        self.params = []

    def __getitem__(self, val):
        self.params.append(self.param_mapping.get(val))
        return '%s'


def format_sql(sql, params):
    rv = []

    if isinstance(params, dict):
        conv = _FormatConverter(params)
        if params:
            sql = sql % conv
            params = conv.params
        else:
            params = ()

    for param in params or ():
        if param is None:
            rv.append('NULL')
        elif isinstance(param, str):
            if isinstance(param, bytes):
                param = param.decode('utf-8', 'replace')
            if len(param) > 256:
                param = param[:256] + u'…'
            rv.append("'%s'" % param.replace("'", "''"))
        elif isinstance(param, JsonAdapter):
            json_obj = str(param)
            if len(json_obj) > 256:
                json_obj = json_obj[:256] + u"…'"
            rv.append(json_obj)
        elif isinstance(param, datetime):
            rv.append("'%s'" % param.isoformat())
        else:
            rv.append(repr(param))

    return sql, rv


def execute_wrapper(*args, **kwargs):
    try:
        return original_execute(*args, **kwargs)
    finally:
        if any(elem in args[0].cursor.statusmessage for elem in ['INSERT', 'UPDATE', 'DELETE', 'MERGE']):
            real_sql, real_params = format_sql(args[1], args[2])
            if real_params:
                real_sql = real_sql % tuple(real_params)

            logger.info('%s', real_sql)


def executemany_wrapper(*args, **kwargs):
    try:
        return original_executemany(*args, **kwargs)
    finally:
        logger.info('%s; args=%s', args[1], args[2])


django.db.backends.utils.CursorWrapper.execute = execute_wrapper
django.db.backends.utils.CursorWrapper.executemany = executemany_wrapper
