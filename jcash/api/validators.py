from datetime import date

from django.utils.deconstruct import deconstructible
from django.core.exceptions import ValidationError
from django.core.validators import BaseValidator
from django.utils.translation import ugettext as _
from rest_framework import serializers


class CustomPasswordValidator:
    def __init__(self, min_length=1):
        self.min_length = min_length

    def validate(self, password, user=None):
        special_characters = "[~\!@#\$%\^&\*\(\)_\+{}\":;'\[\]]"
        if not sum(char.isdigit() for char in password) >= self.min_length:
            raise ValidationError(_('Password must contain at least %(min_length)d digit.') % {'min_length': self.min_length})
        if not sum(char.isalpha() for char in password) >= self.min_length:
            raise ValidationError(_('Password must contain at least %(min_length)d letter.') % {'min_length': self.min_length})
        if not sum(char in special_characters for char in password) >= self.min_length:
            raise ValidationError(_('Password must contain at least %(min_length)d special character.') % {'min_length': self.min_length})

    def get_help_text(self):
        return ""


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
