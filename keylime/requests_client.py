import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.poolmanager import PoolManager  # pylint: disable=import-error


class RequestsClient:
    def __init__(self, base_url, tls_enabled, tls_context=None, ignore_hostname=False, **kwargs):
        if tls_enabled:
            self.base_url = f"https://{base_url}"
        else:
            self.base_url = f"http://{base_url}"

        self.session = requests.Session()

        if ignore_hostname or tls_enabled:
            self.session.mount("http://", HostNameIgnoreAdapter(tls_context, ignore_hostname))
            self.session.mount("https://", HostNameIgnoreAdapter(tls_context, ignore_hostname))

        for arg, value in kwargs.items():
            if isinstance(value, dict):
                value = self.__deep_merge(getattr(self.session, arg), value)
            setattr(self.session, arg, value)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

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

    _tls_context = None
    _ignore_hostname = False

    def __init__(self, tls_context, ignore_hostname, *args, **kwargs):
        self._tls_context = tls_context
        self._ignore_hostname = ignore_hostname

        super().__init__(*args, **kwargs)

    def init_poolmanager(self, connections, maxsize, block=requests.adapters.DEFAULT_POOLBLOCK, **pool_kwargs):
        if self._ignore_hostname and self._tls_context:
            self.poolmanager = PoolManager(
                num_pools=connections,
                maxsize=maxsize,
                block=block,
                strict=True,
                assert_hostname=False,
                ssl_context=self._tls_context,
                **pool_kwargs,
            )
        else:
            self.poolmanager = PoolManager(
                num_pools=connections,
                maxsize=maxsize,
                block=block,
                strict=True,
                ssl_context=self._tls_context,
                **pool_kwargs,
            )
