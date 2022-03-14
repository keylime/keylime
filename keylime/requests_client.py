'''
SPDX-License-Identifier: Apache-2.0
Copyright 2017 Massachusetts Institute of Technology.
'''
import os.path
import tempfile

import requests

from requests.adapters import HTTPAdapter
from requests.packages.urllib3.poolmanager import PoolManager  # pylint: disable=import-error


class RequestsClient:
    def __init__(self, base_url, tls_enabled, ignore_hostname=False, verify_custom: str = False, **kwargs):
        if tls_enabled:
            self.base_url = f'https://{base_url}'
        else:
            self.base_url = f'http://{base_url}'
        self.session = requests.Session()
        if ignore_hostname and tls_enabled:
            self.session.mount("http://", HostNameIgnoreAdapter())
            self.session.mount("https://", HostNameIgnoreAdapter())
        self.verify_custom = verify_custom
        self.temp_dir = None
        for arg, value in kwargs.items():
            if isinstance(value, dict):
                value = self.__deep_merge(
                    getattr(self.session, arg), value)
            setattr(self.session, arg, value)

    def __enter__(self):
        # This is a workaround for SSLContext not being able to load certificates directly
        if self.verify_custom:
            self.temp_dir = tempfile.TemporaryDirectory(prefix="keylime_")
            self.session.verify = os.path.join(self.temp_dir.name, "agent.crt")
            with open(self.session.verify, "w", encoding="utf-8") as f:
                f.write(self.verify_custom)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.temp_dir:
            self.temp_dir.cleanup()

    def request(self, method, url, **kwargs):
        return self.session.request(method, self.base_url + url, **kwargs)

    def head(self, url, **kwargs):
        return self.session.head(self.base_url + url, **kwargs)

    def get(self, url, **kwargs):
        return self.session.get(self.base_url + url, **kwargs)

    def post(self, url, **kwargs):
        return self.session.post(self.base_url + url, **kwargs)

    def put(self, url, **kwargs):
        return self.session.put(self.base_url + url, **kwargs)

    def patch(self, url, **kwargs):
        return self.session.patch(self.base_url + url, **kwargs)

    def delete(self, url, **kwargs):
        return self.session.delete(self.base_url + url, **kwargs)

    @staticmethod
    def __deep_merge(source, destination):
        for key, value in source.items():
            if isinstance(value, dict):
                node = destination.setdefault(key, {})
                RequestsClient.__deep_merge(value, node)
            else:
                destination[key] = value
        return destination


class HostNameIgnoreAdapter(HTTPAdapter):
    """
    This HTTPAdapter just ignores the Hostname validation.

    It is required because in most cases we don't know the hostname during certificate generation.
    """
    def init_poolmanager(self, connections, maxsize, block=requests.adapters.DEFAULT_POOLBLOCK, **pool_kwargs):
        self.poolmanager = PoolManager(num_pools=connections,
                                       maxsize=maxsize,
                                       block=block,
                                       strict=True,
                                       assert_hostname=False, **pool_kwargs)
