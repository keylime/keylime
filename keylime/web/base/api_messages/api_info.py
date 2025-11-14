from typing import Any


class APIInfo:
    """Represents a JSON:API object which contains information about the JSON:API implementation.

    See https://jsonapi.org/format/#document-jsonapi-object
    """

    def __init__(self) -> None:
        self._ext: list[str] = []
        self._profiles: list[str] = []

    def add_ext(self, uri: str) -> "APIInfo":
        self._ext.append(uri)
        return self

    def add_profile(self, uri: str) -> "APIInfo":
        self._profiles.append(uri)
        return self

    def render(self) -> dict[str, Any]:
        output: dict[str, Any] = {}
        output["version"] = self.version

        if self.ext:
            output["ext"] = self.ext

        if self.profiles:
            output["profiles"] = self.profiles

        return output

    @property
    def version(self) -> str:
        return "1.1"

    @property
    def ext(self) -> list[str]:
        return self._ext.copy()

    @property
    def profiles(self) -> list[str]:
        return self._profiles.copy()
