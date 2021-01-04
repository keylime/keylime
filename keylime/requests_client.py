'''
SPDX-License-Identifier: Apache-2.0
Copyright 2017 Massachusetts Institute of Technology.
'''

import requests


class RequestsClient:
    def __init__(self, base_url, tls_enabled, **kwargs):
        if tls_enabled:
            self.base_url = f'https://{base_url}'
        else:
            self.base_url = f'http://{base_url}'
        self.session = requests.Session()
        for arg in kwargs:
            if isinstance(kwargs[arg], dict):
                kwargs[arg] = self.__deep_merge(
                    getattr(self.session, arg), kwargs[arg])
            setattr(self.session, arg, kwargs[arg])

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
