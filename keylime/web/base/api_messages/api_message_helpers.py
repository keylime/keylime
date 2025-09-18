import re


class APIMessageHelpers:
    MEMBER_NAME_REGEX = re.compile("^(@|[a-zA-Z0-9]+:)?[a-zA-Z0-9](?:[a-zA-Z0-9-_]*[a-zA-Z0-9])?$")

    @staticmethod
    def is_valid_name(name):
        """Checks whether the given value adheres to the rules of JSON:API member names.

        See https://jsonapi.org/format/#document-member-names
        """

        if not isinstance(name, str):
            return False

        return bool(APIMessageHelpers.MEMBER_NAME_REGEX.match(name))