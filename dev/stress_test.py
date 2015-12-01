# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import os
import socket
import sys
import textwrap
import time

from oscrypto import tls
from oscrypto.errors import TLSVerificationError
from certvalidator import CertificateValidator, ValidationContext
from certvalidator.errors import PathValidationError, PathBuildingError

if sys.version_info < (3,):
    str_cls = unicode
else:
    str_cls = str

try:
    if sys.stdout.isatty():
        from colorama import init, Fore, Style
        init()
    else:
        raise EnvironmentError()
except (ImportError, EnvironmentError):
    class Fore:
        RED = ''
        YELLOW = ''
        GREEN = ''
        RESET = ''

    class Style:
        DIM = ''
        RESET_ALL = ''


cur_dir = os.path.dirname(__file__)
fixtures_dir = os.path.join(cur_dir, '..', 'tests', 'fixtures')


def run():
    """
    Runs through TLS hosts in the Alexa top 1000 to test TLS functionality

    :return:
        A bool - if the test succeeded without any socket errors
    """

    task_start = time.time()
    success = 0
    tls_errors = 0
    socket_errors = 0
    mismatch_info = []

    context = ValidationContext(allow_fetching=True)

    with open(os.path.join(fixtures_dir, 'alexa_top_1000.csv'), 'rb') as f:
        for line in f:
            domain = line.decode('utf-8').rstrip()
            os_result = None
            cv_result = None
            os_message = None
            cv_message = None

            try:
                os_start = time.time()
                con = tls.TLSSocket(domain, 443, timeout=3)
                con.close()
                success += 1
                os_result = 'OK'
                os_message = 'Success'
                _color('green', 'OK', domain, os_start)
            except (TLSVerificationError) as e:
                tls_errors += 1
                os_result = 'TLS'
                os_message = str_cls(e)
                _color('yellow', 'TLS', domain, os_start, str_cls(e))
            except (socket.error) as e:
                socket_errors += 1
                os_result = 'SOCK'
                os_message = str_cls(e)
                _color('red', 'SOCK', domain, os_start, str_cls(e))

            try:
                cv_start = time.time()
                session = tls.TLSSession(manual_validation=True)
                con = tls.TLSSocket(domain, 443, timeout=3, session=session)
                validator = CertificateValidator(con.certificate, con.intermediates, context)
                validator.validate_tls(domain)
                con.close()
                success += 1
                cv_result = 'OK'
                cv_message = 'Success'
                _color('green', 'OK', domain, cv_start)
            except (PathValidationError, PathBuildingError) as e:
                tls_errors += 1
                cv_result = 'TLS'
                cv_message = str_cls(e)
                _color('yellow', 'TLS', domain, cv_start, str_cls(e))
            except (socket.error) as e:
                socket_errors += 1
                cv_result = 'SOCK'
                cv_message = str_cls(e)
                _color('red', 'SOCK', domain, cv_start, str_cls(e))

            if os_result != cv_result:
                mismatch_info.append([
                    domain,
                    os_result,
                    os_message,
                    cv_result,
                    cv_message
                ])

    total_time = time.time() - task_start
    total_domains = success + tls_errors + socket_errors

    stats = []
    if success > 0:
        stats.append('%d [%sOK%s]' % (success, Fore.GREEN, Fore.RESET))
    if tls_errors > 0:
        stats.append('%d [%sTLS%s]' % (tls_errors, Fore.YELLOW, Fore.RESET))
    if socket_errors > 0:
        stats.append('%d [%sSOCK%s]' % (socket_errors, Fore.RED, Fore.RESET))
    print('')
    print('Checked %d domains in %.3f seconds - %s' % (total_domains, total_time, ' '.join(stats)))

    if mismatch_info:
        print('')
        for info in mismatch_info:
            os_result = '[%s] %s' % (info[1], info[2])
            cv_result = '[%s] %s' % (info[3], info[4])
            _color(
                'red',
                'DIFF',
                'oscrypto and certvalidator results for %s are different' % info[0],
                None,
                os_result,
                cv_result
            )

    return socket_errors == 0


def _color(name, status, text, start=None, *extras):
    """
    Prints a status message with color

    :param name:
        A unicode string of "green", "yellow" or "red" to color the status with

    :param status:
        A unicode string of the status to print

    :param text:
        A unicode string of the text to print after the status

    :param start:
        A float from time.time() of when the status started - used to print
        duration

    :param extras:
        A list of unicode strings of extra information about the status
    """

    color_const = {
        'green': Fore.GREEN,
        'red': Fore.RED,
        'yellow': Fore.YELLOW,
    }[name]

    if start is not None:
        length = round((time.time() - start) * 1000.0)
        duration = '%sms' % length
    else:
        duration = ''

    sys.stdout.write(
        '[%s%s%s] %s %s%s%s\n' % (
            color_const,
            status,
            Fore.RESET,
            text,
            Style.DIM,
            duration,
            Style.RESET_ALL
        )
    )

    for extra in extras:
        indent_len = len(status) + 3
        wrapped_message = '\n'.join(textwrap.wrap(
            extra,
            120,
            initial_indent=' ' * indent_len,
            subsequent_indent=' ' * indent_len
        ))
        message = '%s%s%s' % (Style.DIM, wrapped_message, Style.RESET_ALL)
        try:
            print(message)
        except (UnicodeEncodeError) as e:
            print(message.encode('utf-8'))
