#!/usr/bin/env python3

import argparse
import base64
from urllib.parse import parse_qs, quote, urlencode, urlparse

from google_auth_pb2 import MigrationPayload


def decode_payload(migration_payload):
    for key in migration_payload.otp_parameters:
        url = 'otpauth://'

        if hasattr(key, 'type'):
            if key.type == MigrationPayload.OTP_TYPE_TOTP:
                url += 'totp'
            elif key.type == MigrationPayload.OTP_TYPE_HOTP:
                url += 'hotp'
            else:
                raise ValueError(f'Invalid type: {key.type!r}')
        else:
            raise ValueError('Missing type')

        url += '/'

        if getattr(key, 'issuer', None) and getattr(key, 'name', None):
            url += ':'.join([quote(key.issuer), quote(key.name)])
        elif getattr(key, 'issuer', None):
            url += quote(key.issuer)
        elif getattr(key, 'name', None):
            url += quote(key.name)

        params = {}

        if hasattr(key, 'secret'):
            params['secret'] = base64.b32encode(key.secret).rstrip(b'=')
        else:
            raise ValueError('Missing secret')

        if getattr(key, 'issuer', None):
            params['issuer'] = key.issuer

        if hasattr(key, 'algorithm'):
            if key.algorithm == MigrationPayload.ALGORITHM_MD5:
                params['algorithm'] = 'MD5'
            elif key.algorithm == MigrationPayload.ALGORITHM_SHA1:
                params['algorithm'] = 'SHA1'
            elif key.algorithm == MigrationPayload.ALGORITHM_SHA256:
                params['algorithm'] = 'SHA256'
            elif key.algorithm == MigrationPayload.ALGORITHM_SHA512:
                params['algorithm'] = 'SHA512'
            elif key.algorithm != MigrationPayload.ALGORITHM_UNSPECIFIED:
                raise ValueError(f'Invalid algorithm: {key.algorithm!r}')

        if hasattr(key, 'digits'):
            if key.digits == MigrationPayload.DIGIT_COUNT_SIX:
                params['digits'] = 6
            elif key.digits == MigrationPayload.DIGIT_COUNT_EIGHT:
                params['digits'] = 8
            elif key.digits != MigrationPayload.DIGIT_COUNT_UNSPECIFIED:
                raise ValueError(f'Invalid digit count: {key.digits!r}')

        if key.type == MigrationPayload.OTP_TYPE_HOTP:
            if hasattr(key, 'counter'):
                params['counter'] = key.counter
            else:
                raise ValueError('Missing counter')

        if hasattr(key, 'period') and key.type == MigrationPayload.OTP_TYPE_TOTP:
            params['period'] = key.period

        url += '?' + urlencode(params)
        yield url


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('url', help='otpauth migration URL')
    args = parser.parse_args()

    migration_payload = MigrationPayload()
    query = urlparse(args.url).query
    data = parse_qs(query)['data'][0]
    migration_payload.ParseFromString(base64.b64decode(data))

    for url in decode_payload(migration_payload):
        print(url)
