import sys
import unittest
from io import StringIO

from keylime.policy import logger


def assertDigestsEqual(d1, d2):
    # Ensuring we have only unique values in the digest lists.
    d1_unique = {k: sorted(list(set(v))) for k, v in d1.items()}
    d2_unique = {k: sorted(list(set(v))) for k, v in d2.items()}

    unittest.TestCase().assertEqual(len(d1_unique), len(d2_unique), msg="number of files must match")

    for file in d1_unique:
        unittest.TestCase().assertTrue(file in d2_unique)
        unittest.TestCase().assertEqual(
            len(d1_unique[file]),
            len(d2_unique[file]),
            msg=f"number of files/digests for {file}",
        )

        for d in d1_unique[file]:
            unittest.TestCase().assertTrue(d in d2_unique[file], msg=f"file={file} digest={d}")


# keylime policy logging.
class _KeylimePolicyAssertLogsContext:
    """A context manager for assertLogs() and assertNoLogs()"""

    def __init__(self, no_logs):
        self.logger = logger.Logger(verbose=True)
        self.no_logs = no_logs
        self.stderr = StringIO()

    def __enter__(self):
        self.logger.setStream(self.stderr)
        return self.stderr

    def __exit__(self, exc_type, exc_value, _tb):
        self.logger.setStream(sys.stderr)

        if exc_type is not None:
            # Let unexpected exceptions pass through.
            return False

        logs = "\n".join(self.stderr.getvalue())

        if self.no_logs:
            # assertNoLogs
            if len(logs) > 0:
                raise ValueError(f"Unexpected logs found: {logs}")
        else:
            if len(logs) == 0:
                raise ValueError("No logs triggered on keylime-policy")
        return True


def keylimePolicyAssertNoLogs():
    return _KeylimePolicyAssertLogsContext(no_logs=True)


def keylimePolicyAssertLogs():
    return _KeylimePolicyAssertLogsContext(no_logs=False)
