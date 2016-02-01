# -*- coding:utf-8 -*-

from django.conf import settings
import unicodedata
from validate_email import validate_email, get_mx_ip, MX_CHECK_CACHE, MX_DNS_CACHE
from django.utils.encoding import (smart_text, smart_unicode,
        DjangoUnicodeDecodeError)

class EmailValidationException(Exception):
    pass

class EmailValidation:

    def __init__(self, email, clean=True, validate=True, *args, **kwargs):
        self.dirty_email = email

        try:
            email = smart_unicode(email)
        except DjangoUnicodeDecodeError:
            email = smart_text(email)
        except DjangoUnicodeDecodeError:
            email = smart_text(email)
        except DjangoUnicodeDecodeError:
            email = email.decode('latin1').encode(settings.DEFAULT_CHARSET)
        except UnicodeDecodeError:
            email = email.decode('utf-8').encode(settings.DEFAULT_CHARSET)
        except:
            raise EmailValidationException
        else:

            if clean:
                self.email = self.remove_accents(email)

            if validate:
                self.valid = self.is_valid()

    def remove_accents(self, input_str):
        nfkd_form = unicodedata.normalize('NFKD', input_str)
        return u"".join([c for c in nfkd_form if not unicodedata.combining(c)])

    def is_valid(self, check_mx=True, verify=True, debug=settings.DEBUG, smtp_timeout=10):
        return validate_email(self.email, check_mx, verify, debug, smtp_timeout)

    def validate(self):
        self.hostname = self.email[self.email.find('@') + 1:]
        mx_validation = []

        try:
            mx_hosts = get_mx_ip(self.hostname)
            mx_validation = [(mx[1], MX_CHECK_CACHE[mx[1]]) for mx in mx_hosts \
                    if mx[1] in MX_CHECK_CACHE]
        except Exception as E:
            log.info("Error mx validation\n%s", E)

            pass
            #ServerError: ('DNS query status: SERVFAIL', 2)
                
        return (self.email, self.valid, self.hostname, mx_validation)
