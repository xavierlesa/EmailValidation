# -*- coding:utf-8 -*-

import re
import smtplib
from django.conf import settings
import unicodedata

from django.utils.encoding import (smart_text, smart_unicode,
        DjangoUnicodeDecodeError)

try:
    import DNS
    ServerError = DNS.ServerError
    DNS.DiscoverNameServers()
except (ImportError, AttributeError):
    DNS = None

    class ServerError(Exception):
        pass

# DEPRECAR
#from validate_email import validate_email, get_mx_ip, MX_CHECK_CACHE, MX_DNS_CACHE


# Extraido de validate_email
#
# All we are really doing is comparing the input string to one
# gigantic regular expression.  But building that regexp, and
# ensuring its correctness, is made much easier by assembling it
# from the "tokens" defined by the RFC.  Each of these tokens is
# tested in the accompanying unit test file.
#
# The section of RFC 2822 from which each pattern component is
# derived is given in an accompanying comment.
#
# (To make things simple, every string below is given as 'raw',
# even when it's not strictly necessary.  This way we don't forget
# when it is necessary.)
#
WSP = r'[ \t]'                                       # see 2.2.2. Structured Header Field Bodies
CRLF = r'(?:\r\n)'                                   # see 2.2.3. Long Header Fields
NO_WS_CTL = r'\x01-\x08\x0b\x0c\x0f-\x1f\x7f'        # see 3.2.1. Primitive Tokens
QUOTED_PAIR = r'(?:\\.)'                             # see 3.2.2. Quoted characters
FWS = r'(?:(?:' + WSP + r'*' + CRLF + r')?' + \
      WSP + r'+)'                                    # see 3.2.3. Folding white space and comments
CTEXT = r'[' + NO_WS_CTL + \
        r'\x21-\x27\x2a-\x5b\x5d-\x7e]'              # see 3.2.3
CCONTENT = r'(?:' + CTEXT + r'|' + \
           QUOTED_PAIR + r')'                        # see 3.2.3 (NB: The RFC includes COMMENT here
# as well, but that would be circular.)
COMMENT = r'\((?:' + FWS + r'?' + CCONTENT + \
          r')*' + FWS + r'?\)'                       # see 3.2.3
CFWS = r'(?:' + FWS + r'?' + COMMENT + ')*(?:' + \
       FWS + '?' + COMMENT + '|' + FWS + ')'         # see 3.2.3
ATEXT = r'[\w!#$%&\'\*\+\-/=\?\^`\{\|\}~]'           # see 3.2.4. Atom
ATOM = CFWS + r'?' + ATEXT + r'+' + CFWS + r'?'      # see 3.2.4
DOT_ATOM_TEXT = ATEXT + r'+(?:\.' + ATEXT + r'+)*'   # see 3.2.4
DOT_ATOM = CFWS + r'?' + DOT_ATOM_TEXT + CFWS + r'?' # see 3.2.4
QTEXT = r'[' + NO_WS_CTL + \
        r'\x21\x23-\x5b\x5d-\x7e]'                   # see 3.2.5. Quoted strings
QCONTENT = r'(?:' + QTEXT + r'|' + \
           QUOTED_PAIR + r')'                        # see 3.2.5
QUOTED_STRING = CFWS + r'?' + r'"(?:' + FWS + \
                r'?' + QCONTENT + r')*' + FWS + \
                r'?' + r'"' + CFWS + r'?'
LOCAL_PART = r'(?:' + DOT_ATOM + r'|' + \
             QUOTED_STRING + r')'                    # see 3.4.1. Addr-spec specification
DTEXT = r'[' + NO_WS_CTL + r'\x21-\x5a\x5e-\x7e]'    # see 3.4.1
DCONTENT = r'(?:' + DTEXT + r'|' + \
           QUOTED_PAIR + r')'                        # see 3.4.1
DOMAIN_LITERAL = CFWS + r'?' + r'\[' + \
                 r'(?:' + FWS + r'?' + DCONTENT + \
                 r')*' + FWS + r'?\]' + CFWS + r'?'  # see 3.4.1
DOMAIN = r'(?:' + DOT_ATOM + r'|' + \
         DOMAIN_LITERAL + r')'                       # see 3.4.1
ADDR_SPEC = LOCAL_PART + r'@' + DOMAIN               # see 3.4.1

# A valid address will match exactly the 3.4.1 addr-spec.
VALID_ADDRESS_REGEXP = '^' + ADDR_SPEC + '$'

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


    def is_valid(self, check_mx=True, verify=True, debug=lambda: settings.DEBUG, smtp_timeout=10):
        assert re.match(VALID_ADDRESS_REGEXP, self.email) is not None
        return self.validate_email(self.email, check_mx, verify, debug, smtp_timeout)


    def validate(self):
        self.hostname = self.email[self.email.find('@') + 1:]
        mx_validation = []

        try:
            mx_hosts = self.get_mx_ip(self.hostname)
            mx_validation = [(mx[1], MX_CHECK_CACHE[mx[1]]) for mx in mx_hosts \
                    if mx[1] in MX_CHECK_CACHE]
        except Exception as E:
            log.info("Error mx validation\n%s", E)

            pass
            #ServerError: ('DNS query status: SERVFAIL', 2)
                
        return (self.email, self.valid, self.hostname, mx_validation)


    def resolve_mx(self, email=None, verify=True):
        """
        Intenta resolver los registros MX del dominio

        """

        email = email or self.email
        hostname = email[email.find('@') + 1:]
        mx_hosts = self.get_mx_ip(hostname)

        if mx_hosts is None:
            return False

        for mx in mx_hosts:

            if not verify and mx[1] in MX_CHECK_CACHE:
                return MX_CHECK_CACHE[mx[1]]

            try:
                # Abrea la conexion SMTP para validar contra el servidor
                smtp = smtplib.SMTP(timeout=smtp_timeout)
                smtp.connect(mx[1])

            except smtplib.SMTPServerDisconnected:  # Server not permits verify user
                if debug:
                    logger.debug(u'%s disconected.', mx[1])
            except smtplib.SMTPConnectError:
                if debug:
                    logger.debug(u'Unable to connect to %s.', mx[1])
            else:
                self.smtp_connection = smpt
                MX_CHECK_CACHE[mx[1]] = True

        return mx_hosts


    def validate_email(self, email=None, verify=True, smtp_timeout=10):
        """
        Intenta validar el email si existe y es alcanzable por STMP

        """

        email = email or self.email

        for mx in self.resolve_mx(email):
            try:
                if not verify:
                    try:
                        smtp.quit()
                    except smtplib.SMTPServerDisconnected:
                        pass
                    return True

                status, _ = smtp.helo()

                if status != 250:
                    smtp.quit()
                    if debug:
                        logger.debug(u'%s answer: %s - %s', mx[1], status, _)
                    continue

                smtp.mail('')
                status, _ = smtp.rcpt(email)
                if status == 250:
                    smtp.quit()
                    return True
                if debug:
                    logger.debug(u'%s answer: %s - %s', mx[1], status, _)
                smtp.quit()
            except smtplib.SMTPServerDisconnected:  # Server not permits verify user
                if debug:
                    logger.debug(u'%s disconected.', mx[1])
            except smtplib.SMTPConnectError:
                if debug:
                    logger.debug(u'Unable to connect to %s.', mx[1])
        return None


    MX_DNS_CACHE = {}
    MX_CHECK_CACHE = {}

    def get_mx_ip(self, hostname):
        if hostname not in self.MX_DNS_CACHE:
            try:
                self.MX_DNS_CACHE[hostname] = DNS.mxlookup(hostname)
            except ServerError as e:
                if e.rcode == 3:  # NXDOMAIN (Non-Existent Domain)
                    self.MX_DNS_CACHE[hostname] = None
                else:
                    raise

        return self.MX_DNS_CACHE[hostname]
