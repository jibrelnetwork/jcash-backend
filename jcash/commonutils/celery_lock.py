import logging
import sys
import traceback

from functools import wraps
import redis

from jcash.settings import CELERY_BROKER_URL


REDIS_CLIENT = redis.StrictRedis().from_url(CELERY_BROKER_URL)


def locked_task(name=None, timeout=5*60):
    """Enforce only one celery task at a time."""

    def _dec(run_func):
        """Decorator."""
        key = name or 'celery:{}.{}'.format(run_func.__module__, run_func.__name__)

        @wraps(run_func)
        def _caller(*args, **kwargs):
            """Caller."""
            ret_value = None
            have_lock = False
            lock = REDIS_CLIENT.lock(key, timeout=timeout)
            try:
                have_lock = lock.acquire(blocking=False)
                if have_lock:
                    ret_value = run_func(*args, **kwargs)
            except:
                exception_str = ''.join(traceback.format_exception(*sys.exc_info()))
                logging.getLogger(__name__).error("Failed to get lock for the Celery task '{}' due to error:\n{}"
                                                  .format(run_func.__name__, exception_str))
            finally:
                if have_lock:
                    lock.release()

            return ret_value

        return _caller

    return _dec
