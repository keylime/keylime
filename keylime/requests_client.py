import ssl
from typing import Any, Dict, Optional

import requests
from requests.adapters import DEFAULT_POOLBLOCK, HTTPAdapter
from requests.packages.urllib3.poolmanager import PoolManager  # pylint: disable=import-error


class RequestsClient:
    def __init__(
        self,
        base_url: str,
        tls_enabled: bool,
        tls_context: Optional[ssl.SSLContext] = None,
        ignore_hostname: bool = True,
        **kwargs: Any,
    ) -> None:
        if tls_enabled:
            self.base_url = f"https://{base_url}"
        else:
            self.base_url = f"http://{base_url}"

        self.session = requests.Session()

        if tls_enabled:
            self.session.mount("http://", HostNameIgnoreAdapter(tls_context, ignore_hostname))
            self.session.mount("https://", HostNameIgnoreAdapter(tls_context, ignore_hostname))

        for arg, value in kwargs.items():
            if isinstance(value, dict):
                value = self.__deep_merge(getattr(self.session, arg), value)
            setattr(self.session, arg, value)

    def __enter__(self) -> "RequestsClient":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        pass

    def request(self, method: str, url: str, **kwargs: Any) -> requests.Response:
        return self.session.request(method, self.base_url + url, **kwargs)

    def head(self, url: str, **kwargs: Any) -> requests.Response:
        return self.session.head(self.base_url + url, **kwargs)

    def get(self, url: str, **kwargs: Any) -> requests.Response:
        return self.session.get(self.base_url + url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> requests.Response:
        return self.session.post(self.base_url + url, **kwargs)

    def put(self, url: str, **kwargs: Any) -> requests.Response:
        return self.session.put(self.base_url + url, **kwargs)

    def patch(self, url: str, **kwargs: Any) -> requests.Response:
        return self.session.patch(self.base_url + url, **kwargs)

    def delete(self, url: str, **kwargs: Any) -> requests.Response:
        return self.session.delete(self.base_url + url, **kwargs)

    @staticmethod
    def __deep_merge(source: Dict[Any, Any], destination: Dict[Any, Any]) -> Dict[Any, Any]:
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

    def __init__(self, tls_context: Optional[ssl.SSLContext], ignore_hostname: bool, *args: Any, **kwargs: Any) -> None:
        self._tls_context = tls_context
        self._ignore_hostname = ignore_hostname

        super().__init__(*args, **kwargs)

    def init_poolmanager(
        self, connections: int, maxsize: int, block: bool = DEFAULT_POOLBLOCK, **pool_kwargs: Any
    ) -> None:
        assert_hostname = False if self._ignore_hostname and self._tls_context else None
        self.poolmanager = PoolManager(
            num_pools=connections,
            maxsize=maxsize,
            block=block,
            strict=True,
            assert_hostname=assert_hostname,
            ssl_context=self._tls_context,
            **pool_kwargs,
        )
