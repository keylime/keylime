

class APIInfo:
    """Represents a JSON:API object which contains information about the JSON:API implementation.

    See https://jsonapi.org/format/#document-jsonapi-object
    """

    def __init__(self):
        self._ext = []
        self._profiles = []

    def add_ext(self, uri):
        self._ext.append(uri)

    def add_profile(self, uri):
        self._profiles.append(uri)

    def render(self):
        output = {}
        output["version"] = self.version

        if self.ext:
            output["ext"] = self.ext

        if self.profiles:
            output["profiles"] = self.profiles

        return output

    @property
    def version(self):
        return "1.1"

    @property
    def ext(self):
        return self._ext.copy()

    @property
    def profiles(self):
        return self._profiles.copy()