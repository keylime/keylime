'''
SPDX-License-Identifier: BSD-2-Clause
Copyright 2020 Red Hat, Luke Hinds <lhinds@redhat.com>
'''

import jwt
from keylime import common

AUTHORIZATION_HEADER = 'Authorization'
AUTHORIZATION_METHOD = 'bearer'
INVALID_HEADER_MESSAGE = "invalid header authorization"
MISSING_AUTHORIZATION_KEY = "Missing authorization"
AUTHORIZTION_ERROR_CODE = 401

jwt_options = {
    'verify_signature': True,
    'verify_exp': True,
    'verify_nbf': False,
    'verify_iat': True,
    'verify_aud': False
}

config = common.get_config()

jwt_hmac_passphrase = config.get('cloud_verifier', 'jwt_hmac_passphrase')
jwt_dsa = config.get('cloud_verifier', 'jwt_dsa')


def is_valid_header(parts):
    """
        Validate the header
    """
    if parts[0].lower() != AUTHORIZATION_METHOD:
        return False
    elif len(parts) == 1:
        return False
    elif len(parts) > 2:
        return False

    return True


def return_auth_error(handler, message):
    """
        Return authorization error
    """
    handler._transforms = []
    handler.set_status(AUTHORIZTION_ERROR_CODE)
    handler.write(message)
    handler.finish()


def return_header_error(handler):
    """
        Returh authorization header error
    """
    return_auth_error(handler, INVALID_HEADER_MESSAGE)


def jwtauth(handler_class):
    """
        Tornado JWT Auth Decorator
    """
    def wrap_execute(handler_execute):
        def require_auth(handler, kwargs):

            auth = handler.request.headers.get(AUTHORIZATION_HEADER)
            if auth:
                parts = auth.split()

                if not is_valid_header(parts):
                    return_header_error(handler)

                token = parts[1]
                try:
                    jwt.decode(
                        token,
                        jwt_hmac_passphrase,
                        options=jwt_options
                    )
                except Exception as err:
                    return_auth_error(handler, str(err))

            else:
                handler._transforms = []
                handler.write(MISSING_AUTHORIZATION_KEY)
                handler.finish()

            return True

        def _execute(self, transforms, *args, **kwargs):

            try:
                require_auth(self, kwargs)
            except Exception:
                return False

            return handler_execute(self, transforms, *args, **kwargs)

        return _execute

    handler_class._execute = wrap_execute(handler_class._execute)
    return handler_class
