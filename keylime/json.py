"""
SPDX-License-Identifier: Apache-2.0
Copyright 2021 Sergio Correia (scorreia@redhat.com), Red Hat, Inc.
"""

import json as json_module


_list_types = [list, tuple]
try:
    from sqlalchemy.engine.row import Row  # sqlalchemy >= 1.4.

    _list_types.append(Row)
except ModuleNotFoundError:
    try:
        from sqlalchemy.engine import RowProxy

        _list_types.append(RowProxy)
    except ModuleNotFoundError:
        pass


def __bytes_to_str(data):
    if isinstance(data, (bytes, bytearray)):
        data = data.decode("utf-8")
    elif isinstance(data, dict):
        for _k, _v in data.items():
            data[_k] = __bytes_to_str(_v)
    elif isinstance(data, tuple(_list_types)):
        _l = list(data)
        for _k, _v in enumerate(_l):
            _l[_k] = __bytes_to_str(_v)
        data = _l

    return data


def dumps(obj, **kwargs):
    try:
        ret = json_module.dumps(obj, **kwargs)
    except TypeError:
        # dumps() from the built-it json module does not work with bytes,
        # so let's convert those to str if we get a TypeError exception.
        ret = json_module.dumps(__bytes_to_str(obj), **kwargs)
    return ret


def dump(obj, fp, **kwargs):
    try:
        json_module.dump(obj, fp, **kwargs)
    except TypeError:
        # dump() from the built-it json module does not work with bytes,
        # so let's convert those to str if we get a TypeError exception.
        json_module.dump(obj, fp, **kwargs)


def load(fp, **kwargs):
    return json_module.load(fp, **kwargs)


def loads(s, **kwargs):
    return json_module.loads(s, **kwargs)


# JSON pickler that fulfills SQLAlchemy requirements, from
# social-storage-sqlalchemy.
# https://github.com/python-social-auth/social-storage-sqlalchemy/commit/39d129
class JSONPickler:
    """JSON pickler wrapper around json lib since SQLAlchemy invokes
    dumps with extra positional parameters"""

    @classmethod
    def dumps(cls, value, *args, **kwargs):
        # pylint: disable=unused-argument
        """Dumps the python value into a JSON string"""
        return dumps(value)

    @classmethod
    def loads(cls, value):
        """Parses the JSON string and returns the corresponding python value"""
        return loads(value)
