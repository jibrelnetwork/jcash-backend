from datetime import date

from django.utils.deconstruct import deconstructible
from django.core.exceptions import ValidationError
from django.core.validators import BaseValidator
from django.utils.translation import ugettext as _
from rest_framework import serializers


def calculate_age(born):
    today = date.today()
    return today.year - born.year - \
           ((today.month, today.day) < (born.month, born.day))


@deconstructible
class BirthdayValidator(BaseValidator):
    def __init__(self, min_age):
        self.min_age = min_age

    def __call__(self, value):
        today = date.today()
        if value.year < 1900:
            raise serializers.ValidationError('Please enter a valid birth date')
        elif today <= value:
            raise serializers.ValidationError('Please enter a valid birth date')
        elif calculate_age(value) < self.min_age:
            raise serializers.ValidationError('Age must be at least {}'.format(self.min_age))
