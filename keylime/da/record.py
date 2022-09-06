import base64
import errno
import importlib
import os
import pickle
import tempfile
from datetime import datetime

from keylime import config, crypto, json, keylime_logging
from keylime.fs_util import ch_dir
from keylime.web_util import init_mtls

logger = keylime_logging.init_logging("persistent_store")


class BaseRecordManagement:
    def __init__(self, service):

        self.svc = service

        self.ps_url = config.get(self.svc, "persistent_store_url", fallback="")
        self.tl_url = config.get(self.svc, "transparency_log_url", fallback="")
        self.tsa_url = config.get(self.svc, "time_stamp_authority_url", fallback="")
        self.tsa_cert = config.get(self.svc, "time_stamp_authority_certs_path", fallback="")

        self.st_imp_path = ".".join(config.get(self.svc, "durable_attestation_import", fallback="").split(".")[0:-1])

        self.rmv_a = ["ssl_context", "pending_event", "b64_encrypted_V"]
        self.rcd_fmt = config.get(self.svc, "persistent_store_format", fallback="pickle")
        self.rcd_enc = config.get(self.svc, "persistent_store_encoding", fallback="none")
        self.rcd_sa = config.get(self.svc, "transparency_log_sign_algo", fallback="sha256")
        self.tmp_d_cl = True
        self.cert_tls_priv = None
        self.cert_tls_pub = None
        self.priv_key = None

    def record_create(self, agent_data, attestation_data, ima_policy_data, service="auto", signed_attributes="auto"):
        logger.debug(
            "Received paramaters: %s, %s, %s, %s, %s",
            str(agent_data),
            str(attestation_data),
            str(ima_policy_data),
            service,
            signed_attributes,
        )

    def agent_list_retrieval(self, agent_list, record_prefix="auto", service="auto"):
        logger.debug("Received paramaters: %s, %s, %s", agent_list, record_prefix, service)

    def bulk_record_retrieval(self, record_identifier, record_list):
        logger.debug("Received paramaters: %s, %s", record_identifier, record_list)

    def build_key_list(self, agent_identifier, aik_list, service="auto"):
        logger.debug("Received paramaters: %s, %s, %s", agent_identifier, str(aik_list), service)

    def record_read(self, attestation_record_list, agent_identifier, service="auto"):
        logger.debug("Received paramaters: %s, %s, %s", str(attestation_record_list), agent_identifier, service)

    def _get_record_type(self, service):
        if service != "auto":
            self.svc = service

        if self.svc == "registrar":
            return "registration"

        return "attestation"

    def _get_certs_path(self, override_service=None):

        if override_service:
            self.svc = override_service

        _, _certs = init_mtls(section=self.svc, logger=logger, generate_context=False)

        self.cert_tls_priv = _certs[1]
        self.cert_tls_pub = _certs[1].replace("-private", "-public")

        with open(self.cert_tls_priv, "rb") as fp:
            self.priv_key = crypto.rsa_import_privkey(fp.read())

    def _record_encode(self, record_object):
        """Encodes record"""

        _encoded_record_object = record_object

        if self.rcd_fmt == "pickle":
            _encoded_record_object = pickle.dumps(record_object)

        if self.rcd_fmt == "json":
            _encoded_record_object = json.dumps(record_object, indent=4)
            if self.rcd_enc == "base64":
                _encoded_record_object = str.encode(_encoded_record_object)

        if self.rcd_enc == "base64":
            _encoded_record_object = base64.b64encode(_encoded_record_object)

        return _encoded_record_object

    def _record_decode(self, record_object):
        """Decodes record"""

        _decoded_record_object = record_object

        if self.rcd_enc == "base64":
            _decoded_record_object = base64.b64decode(_decoded_record_object)

        if self.rcd_fmt == "pickle":
            _decoded_record_object = pickle.loads(_decoded_record_object)

        if self.rcd_fmt == "json":
            if self.rcd_enc == "base64":
                _decoded_record_object = _decoded_record_object.decode("utf-8")
            _decoded_record_object = json.loads(_decoded_record_object)

        return _decoded_record_object

    def _record_sanitize(self, record_object):
        """Removes complex python objects from record"""
        for _key in self.rmv_a:
            if _key in record_object["agent"]:
                record_object["agent"][_key] = None

    def _record_assemble(self, record_object, agent_data, attestation_data, ima_policy_data):
        """Assemble record to be created on persistent datastore"""
        if "agent" not in record_object:
            record_object["agent"] = {}
            record_object["agent"].update(agent_data)

        self._record_sanitize(record_object)

        if attestation_data:
            record_object["json_response"] = attestation_data

        if ima_policy_data:
            record_object["ima_policy"] = ima_policy_data

    def _record_assemble_for_signing(self, record_to_sign, agent_data, attestation_data, signed_attributes):
        """Builds a dictionary of attributes to dumped into a JSON file to be signed"""
        if not signed_attributes:
            return None

        if signed_attributes == "all":
            record_to_sign["agent"] = {}
            record_to_sign["agent"].update(agent_data)

            if attestation_data:
                record_to_sign["json_response"] = {}
                record_to_sign["json_response"].update(attestation_data)
        else:
            try:
                signed_attributes = signed_attributes.split(",")
            except Exception:
                pass

            record_to_sign["agent"] = {}
            for _attr in signed_attributes:
                if _attr in agent_data:
                    record_to_sign["agent"][_attr] = agent_data[_attr]

        self._record_sanitize(record_to_sign)
        return None

    def _build_key_list(self, registration_record_list, aik_list):
        """Just assembles a simple list of AIKs used by an agent"""

        for _entry in registration_record_list:
            if _entry["agent"]["aik_tpm"] not in aik_list:
                logger.debug("New AIK added to the list")
                aik_list.append(_entry["agent"]["aik_tpm"])

    def _record_create(self, record_object, agent_data, attestation_data, ima_policy_data):
        """Prepares record to be created on persistent datastore"""
        self._record_assemble(record_object, agent_data, attestation_data, ima_policy_data)

        record_object[self.svc + "_timestamp"] = datetime.now().strftime("%m/%d/%Y, %H:%M:%S")

        return self._record_encode(record_object)

    def _record_read(self, attestation_record_list):
        assert attestation_record_list

    def _record_signature_create(self, record_object, agent_data, attestation_data, service, signed_attributes):
        """Sign a record with openssl"""

        if signed_attributes == "auto":
            signed_attributes = config.get(self.svc, "signed_attributes", fallback="")

        if service != "auto":
            self.svc = service

        self._record_assemble_for_signing(record_object, agent_data, attestation_data, signed_attributes)

        if not record_object or not self.tl_url:
            return None

        self._get_certs_path()

        _temp_dir_path = tempfile.mkdtemp()

        ch_dir("/".join(self.cert_tls_priv.split("/")[0:-1]))
        if not os.path.exists(self.cert_tls_pub):
            raise RecordManagementException(
                f"Unable to find public key {self.cert_tls_pub} while signing data for agent {agent_data['agent_id']}"
            )
        #            command = [
        #                "openssl",
        #                "ecparam",
        #                "-genkey",
        #                "-name",
        #                "prime256v1",
        #                ">",
        #                self.cert_tls_priv
        #            ]
        #            retDict = run(cmd=command)

        #            command = [
        #                "openssl",
        #                "ec",
        #                "-in",
        #                self.cert_tls_priv,
        #                "-pubout",
        #                ">",
        #                self.cert_tls_pub
        #            ]
        #            retDict = run(cmd=command)

        _contents = json.dumps(record_object).encode("utf-8")
        with open(_temp_dir_path + "/" + agent_data["agent_id"] + ".json", "wb") as fp:
            fp.write(_contents)

        record_object["temp_dir"] = _temp_dir_path
        record_object["contents_file_path"] = record_object["temp_dir"] + "/" + agent_data["agent_id"] + ".json"
        record_object["signature_file_path"] = record_object["temp_dir"] + "/" + agent_data["agent_id"] + ".json.sig"

        #        command = [
        #            "openssl",
        #            "dgst",
        #            '-' + self.rcd_sa,
        #            "-sign",
        #            self.cert_tls_priv,
        #            "-keyform",
        #            "PEM",
        #            "-binary",
        #            "-out",
        #            record_object["signature_file_path"],
        #            record_object["contents_file_path"]
        #        ]
        #        retDict = run(cmd=command)

        #        fp = open(record_object["signature_file_path"],"rb")
        #        record_object["signature"] = base64.b64encode(fp.read())
        #        fp.close()

        with open(self.cert_tls_pub, encoding="utf-8") as fp:
            record_object["signer_pub_key"] = fp.read()

        record_object["signature"] = crypto.rsa_sign(self.priv_key, _contents, "default")

        with open(record_object["signature_file_path"], "wb") as fp:
            fp.write(base64.b64decode(record_object["signature"]))

        self._record_timestamp_create(record_object, agent_data["agent_id"], _contents)
        return None

    def _record_timestamp_create(self, record_object, agent_id, contents):
        if self.tsa_url:

            #            record_object["signature_timestamp_file_path"] = record_object["temp_dir"]  + '/' + agent_id + ".json.tsq"

            #            command = [
            #                "openssl",
            #                "ts",
            #                "-query",
            #                "-data",
            #                record_object["contents_file_path"] ,
            #                "-no_nonce",
            #                '-' + self.rcd_sa,
            #                "-cert",
            #                "-out",
            #                record_object["signature_timestamp_file_path"]
            #            ]
            #            retDict = run(cmd=command)

            #            fp = open(record_object["signature_timestamp_file_path"],"rb")
            #            record_object["timestamp_request"] = base64.b64encode(fp.read())
            #            fp.close()

            logger.debug("Obtaining a time stamp for data referring to agent %s from TSA at %s", agent_id, self.tsa_url)

            import rfc3161ng  # pylint: disable=import-outside-toplevel

            if self.tsa_cert:
                with open(self.tsa_cert, "rb") as fp:
                    _certificate = fp.read()

            _rt = rfc3161ng.RemoteTimestamper(self.tsa_url, certificate=_certificate)
            _tst = _rt.timestamp(data=contents)
            if _rt.check(_tst, data=contents):
                record_object["signature_timestamp_response"] = base64.b64encode(_tst)
            else:
                raise RecordManagementException(f"Failure while timestamping data for agent {agent_id}")

    def _record_timestamp_check(self, record_object, contents):
        if self.tsa_url:

            logger.debug("Checking the time stamp for object from TSA at %s", self.tsa_url)

            import rfc3161ng  # pylint: disable=import-outside-toplevel

            if self.tsa_cert:
                with open(self.tsa_cert, "rb") as fp:
                    _certificate = fp.read()

            _rt = rfc3161ng.RemoteTimestamper(self.tsa_url, certificate=_certificate)
            _tst = base64.b64decode(record_object["signature_timestamp_response"])
            if not _rt.check(_tst, data=contents):
                raise RecordManagementException("Failure while timestamping data")

    def _record_signature_check(self, record_object):
        """Check the signature for a record"""

        if not "signature" in record_object:
            return None

        self._get_certs_path()

        _temp_dir_path = tempfile.mkdtemp()

        record_object["temp_dir"] = _temp_dir_path
        record_object["contents_file_path"] = record_object["temp_dir"] + "/" + "object" + ".json"
        record_object["signature_file_path"] = record_object["temp_dir"] + "/" + "object" + ".json.sig"

        with open(record_object["signature_file_path"], "wb") as fp:
            try:
                record_object["signature"] = str.encode(record_object["signature"])
            except Exception:
                pass
            fp.write(base64.decodebytes(record_object["signature"]))

        with open(self.cert_tls_pub, "w", encoding="utf-8") as fp:
            fp.write(record_object["signer_pub_key"])

        _contents_to_check = {}
        _contents_to_check["agent"] = record_object["agent"]
        #        if "json_response" in record_object :
        #            _contents_to_check["json_response"]

        _contents_to_check = json.dumps(_contents_to_check).encode("utf-8")

        self._record_timestamp_check(record_object, _contents_to_check)

        with open(record_object["contents_file_path"], "wb") as fp:
            fp.write(_contents_to_check)
        return None

    def mkdir_p(self, path):
        try:
            os.makedirs(path)
        except OSError as exc:  # Python >2.5
            if exc.errno == errno.EEXIST and os.path.isdir(path):
                pass
            else:
                raise


class RecordManagementException(Exception):
    pass


def get_record_mgt_class(store_import=None):
    if store_import:
        return getattr(importlib.import_module(store_import), "RecordManagement")
    return BaseRecordManagement
