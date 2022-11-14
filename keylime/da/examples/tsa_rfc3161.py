import base64

import rfc3161ng

from keylime import keylime_logging
from keylime.da.record import RecordManagementException

logger = keylime_logging.init_logging("durable_attestation_time_stamp_authority")


def record_timestamp_create(record_object, agent_id, contents, tsa_url, tsa_cert):
    if tsa_url:
        if tsa_cert:
            with open(tsa_cert, "rb") as fp:
                _certificate = fp.read()

        _rt = rfc3161ng.RemoteTimestamper(tsa_url._replace(fragment="").geturl(), certificate=_certificate)
        _tst = _rt.timestamp(data=contents)
        if _rt.check(_tst, data=contents):
            record_object["signature_timestamp_response"] = base64.b64encode(_tst)
        else:
            raise RecordManagementException(f"Failure while timestamping data for agent {agent_id}")


def record_timestamp_check(record_object, agent_id, contents, tsa_url, tsa_cert):
    if tsa_url:

        if tsa_cert:
            with open(tsa_cert, "rb") as fp:
                _certificate = fp.read()

        _rt = rfc3161ng.RemoteTimestamper(tsa_url, certificate=_certificate)
        _tst = base64.b64decode(record_object["signature_timestamp_response"])
        if not _rt.check(_tst, data=contents):
            raise RecordManagementException(f"Failure while check timestamp of data for agent {agent_id}")
