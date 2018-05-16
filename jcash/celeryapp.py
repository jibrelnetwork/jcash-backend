import os

import celery
import django.conf

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'jcash.settings')

celery_app = celery.Celery(
    'jcash',
    backend=django.conf.settings.CELERY_RESULT_BACKEND,
    broker=django.conf.settings.CELERY_BROKER_URL,
)
celery_app.config_from_object('django.conf:settings', namespace='CELERY')
celery_app.autodiscover_tasks()
