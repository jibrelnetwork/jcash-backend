from rest_framework import serializers
from django.utils.translation import ugettext_lazy as _


class CustomDateField(serializers.DateField):
    def __init__(self, *args, **kwargs):
        super(CustomDateField, self).__init__(*args, **kwargs)
        self.error_messages = {
            'invalid': _('Date has wrong format.'),
            'datetime': _('Expected a date but got a datetime.'),
        }
