
from datetime import datetime, timedelta
import logging

from django.contrib.auth import get_user_model
from django.conf import settings
from django.db.models import Q
from django.db import transaction
from django.utils import timezone

from jcash.api.models import Account, Notification


logger = logging.getLogger(__name__)


MAX_VERIFICATION_ATTEMPTS = 3
