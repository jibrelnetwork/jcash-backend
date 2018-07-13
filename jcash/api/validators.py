from django.core.exceptions import ValidationError
from django.utils.translation import ugettext as _


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
