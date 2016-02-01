# -*- coding:utf-8 -*-

from django.forms.fields import EmailField
from django.core.exceptions import ValidationError
from django.utils.translation import ugettext_lazy as _
from .emailvalidation import EmailValidation, EmailValidationException


class EmailValidationField(EmailField):
    def validate(self, value):
        super(EmailValidationField, self).validate(value)

        email_validation = EmailValidation(value, validate=False)

        if not email_validation.is_valid():
            raise ValidationError(_(u"El Email no existe o no es valido"))
