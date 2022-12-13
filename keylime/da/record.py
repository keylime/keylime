import abc
import base64
import copy
import importlib
import os
import pickle
import tempfile
from datetime import datetime
from typing import Any, Dict, List, Optional, Union
from urllib.parse import urlparse

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from keylime import config, crypto, json, keylime_logging, web_util
from keylime.fs_util import ch_dir

logger = keylime_logging.init_logging("durable_attestation")


class BaseRecordManagement(metaclass=abc.ABCMeta):
    def __init__(self, service: str, key_tls_pub: Optional[str] = "") -> None:

        self.svc = service

        self.ps_url = urlparse(config.get(self.svc, "persistent_store_url", fallback=""))
        self.tl_url = urlparse(config.get(self.svc, "transparency_log_url", fallback=""))
        self.tsa_url = urlparse(config.get(self.svc, "time_stamp_authority_url", fallback=""))
        self.tsa_cert = config.get(self.svc, "time_stamp_authority_certs_path", fallback="")

        self.st_imp_module = config.get(self.svc, "durable_attestation_import", fallback="")
        self.st_imp_path = ".".join(self.st_imp_module.split(".")[0:-1])

        self.rmv_a = ["ssl_context", "pending_event"]
        self.rcd_fmt = config.get(self.svc, "persistent_store_format", fallback="json")
        self.rcd_enc = config.get(self.svc, "persistent_store_encoding", fallback="")
        self.rcd_sa = config.get(self.svc, "transparency_log_sign_algo", fallback="sha256")
        self.tmp_d_cl = True
        self.key_tls_priv: Optional[str] = ""
        self.key_tls_pub = key_tls_pub
        self.priv_key: Optional[RSAPrivateKey] = None
        self.start_of_times = 0
        self.end_of_times = 99999999999
        logger.info('The "Durable Attestion" feature is stil experimental and might change in the future')
        logger.debug('Persistent store module %s imported for "Durable Attestation"', self.st_imp_module)

    @abc.abstractmethod
    def record_create(
        self,
        agent_data: Dict[Any, Any],
        attestation_data: Dict[Any, Any],
        ima_policy_data: Dict[Any, Any],
        service: str = "auto",
        signed_attributes: str = "auto",
    ) -> None:
        """Takes agent data, attestation data, ima policy data, serialize, optionally encodes it and writes to a persistent data store"""

    def get_record_type(self, service: str) -> str:
        """Determine which "service", (initial) registration or attestation is used)"""
        if service != "auto":
            self.svc = service

        if self.svc == "registrar":
            return "registration"

        return "attestation"

    def set_certs_path(self, override_service: Optional[str] = "") -> None:
        """Get the paths for TLS certficates and key pair (used for agent data attribute signature, optionally) from the Keylime configurations"""
        if override_service:
            self.svc = override_service

        if not self.key_tls_pub:
            (_, self.key_tls_priv, _, _), _ = web_util.get_tls_options(self.svc, logger=logger)

            if self.key_tls_priv:
                self.key_tls_pub = self.key_tls_priv.replace("-private", "-public")

                if self.tl_url:
                    with open(self.key_tls_priv, "rb") as fp:
                        self.priv_key = crypto.rsa_import_privkey(fp.read())

    def record_serialize(self, record_object: Dict[Any, Any]) -> Union[Any, Dict[Any, Any]]:
        """Serialize, and optionally encodes, record"""

        manipulated_record_object = copy.deepcopy(record_object)

        if self.rcd_fmt == "pickle":
            serialized_record_object = pickle.dumps(manipulated_record_object)

        if self.rcd_fmt == "json":
            serialized_record_object = json.dumps(manipulated_record_object, indent=4).encode("utf-8")

        if self.rcd_enc == "base64":
            serialized_record_object = base64.b64encode(serialized_record_object)

        return serialized_record_object

    def record_deserialize(self, record_object: Union[Any, bytes]) -> Union[Any, Dict[Any, Any]]:
        """Deserialize, and optionally decodes, record"""

        manipulated_record_object = copy.deepcopy(record_object)

        if self.rcd_enc == "base64":
            manipulated_record_object = base64.b64decode(manipulated_record_object)

        if self.rcd_fmt == "pickle":
            deserialized_record_object = pickle.loads(manipulated_record_object)

        if self.rcd_fmt == "json":
            deserialized_record_object = manipulated_record_object.decode("utf-8")
            deserialized_record_object = json.loads(deserialized_record_object)

        return deserialized_record_object

    def record_sanitize(self, record_object: Dict[Any, Any]) -> Dict[Any, Any]:
        """Removes a set of pre-defined key,pairs from record"""

        # copy.deepcopy fails at "ssl_context"

        sanitized_record_object: Dict[Any, Any] = {}

        for key in record_object:
            if isinstance(record_object[key], dict):
                if key not in sanitized_record_object:
                    sanitized_record_object[key] = {}
                for subkey in record_object[key]:
                    if subkey not in self.rmv_a:
                        sanitized_record_object[key][subkey] = record_object[key][subkey]
            else:
                sanitized_record_object[key] = record_object[key]

        return sanitized_record_object

    def record_assemble(
        self,
        record_object: Dict[Any, Any],
        agent_data: Dict[Any, Any],
        attestation_data: Dict[Any, Any],
        ima_policy_data: Dict[Any, Any],
    ) -> Dict[Any, Any]:
        """Assemble record to be created on persistent datastore"""

        record_object_assembled = copy.deepcopy(record_object)

        if "agent" not in record_object_assembled:
            record_object_assembled["agent"] = {}
            record_object_assembled["agent"].update(agent_data)

        sanitized_and_assembled_record_object = self.record_sanitize(record_object_assembled)

        if attestation_data:
            sanitized_and_assembled_record_object["json_response"] = attestation_data

        if ima_policy_data:
            sanitized_and_assembled_record_object["ima_policy"] = ima_policy_data

        return sanitized_and_assembled_record_object

    def record_assemble_for_signing(
        self,
        record_to_sign: Dict[Any, Any],
        agent_data: Dict[Any, Any],
        attestation_data: Dict[Any, Any],
        signed_attributes: str,
    ) -> Dict[Any, Any]:
        """Builds a dictionary of attributes to dumped into a JSON file to be signed"""
        if not signed_attributes:
            return {}

        if signed_attributes == "all":
            record_to_sign["agent"] = {}
            record_to_sign["agent"].update(agent_data)

            if attestation_data:
                record_to_sign["json_response"] = {}
                record_to_sign["json_response"].update(attestation_data)
        else:
            record_to_sign["agent"] = {}
            for _attr in signed_attributes.split(","):
                if _attr in agent_data:
                    record_to_sign["agent"][_attr] = agent_data[_attr]

        return self.record_sanitize(record_to_sign)

    def base_record_create(
        self,
        record_object: Dict[Any, Any],
        agent_data: Dict[Any, Any],
        attestation_data: Dict[Any, Any],
        ima_policy_data: Dict[Any, Any],
    ) -> Union[bytes, Dict[Any, Any]]:
        """Prepares record to be stored on persistent datastore"""
        record_assembled = self.record_assemble(record_object, agent_data, attestation_data, ima_policy_data)

        record_assembled[self.svc + "_timestamp"] = datetime.now().strftime("%m/%d/%Y, %H:%M:%S")

        return self.record_serialize(record_assembled)

    def base_record_read(self, attestation_record_list: List[Dict[Any, Any]]) -> None:
        """Accesses a persisent data store, retrieves multiple data entries, adding each entry to a provided list"""
        assert self.svc
        assert attestation_record_list

    def base_record_signature_create(
        self,
        record_object: Dict[Any, Any],
        agent_data: Dict[Any, Any],
        attestation_data: Dict[Any, Any],
        service: str,
        signed_attributes: str,
    ) -> bytes:
        """
        Sign a record with with a private (RSA) key from Keylime

        The parameter "signed attributes" can receive the value "auto", which
        results in this value being read from the configuration file.
        """

        contents_for_signing = b""
        if signed_attributes == "auto":
            signed_attributes = config.get(self.svc, "signed_attributes", fallback="")

        if service != "auto":
            self.svc = service

        record_object_for_signing = self.record_assemble_for_signing(
            record_object, agent_data, attestation_data, signed_attributes
        )

        if not record_object_for_signing:
            logger.debug(
                "No attributes specified to be signed. Will skip signing of data referring to agent %s",
                agent_data["agent_id"],
            )
            return contents_for_signing

        if not self.tl_url.scheme:
            logger.debug(
                "No Transparency Log URL specified. Will skip signing of data referring to agent %s",
                agent_data["agent_id"],
            )
            return contents_for_signing

        logger.debug(
            "Recording signature of attributes %s at Transparencey Log %s for data referring to agent %s",
            signed_attributes,
            self.tl_url._replace(fragment="").geturl(),
            agent_data["agent_id"],
        )

        self.set_certs_path()

        with tempfile.TemporaryDirectory() as _temp_dir_path:

            if self.key_tls_pub:

                ch_dir("/".join(self.key_tls_pub.split("/")[0:-1]))
                if not os.path.exists(self.key_tls_pub):
                    raise RecordManagementException(
                        f"Unable to find public key {self.key_tls_pub} while signing data for agent {agent_data['agent_id']}"
                    )

                contents_for_signing = json.dumps(record_object_for_signing).encode("utf-8")
                with open(f'{_temp_dir_path}/{agent_data["agent_id"]}.json', "wb") as fp:
                    fp.write(contents_for_signing)

                record_object["temp_dir"] = _temp_dir_path
                record_object["contents_file_path"] = f'{record_object["temp_dir"]}/{agent_data["agent_id"]}.json'
                record_object["signature_file_path"] = f'{record_object["temp_dir"]}/{agent_data["agent_id"]}.json.sig'

                with open(self.key_tls_pub, encoding="utf-8") as fp:
                    record_object["signer_pub_key"] = fp.read()

                if self.priv_key:
                    record_object["signature"] = crypto.rsa_sign(self.priv_key, contents_for_signing, "default")

                with open(record_object["signature_file_path"], "wb") as fp:
                    fp.write(base64.b64decode(record_object["signature"]))

                if "contents_file_path" in record_object and "signature_file_path" in record_object:
                    if self.tl_url.scheme == "http" and self.tl_url.netloc.count("3000"):
                        getattr(importlib.import_module(self.st_imp_path + ".rekor"), "record_signature_create")(
                            record_object, agent_data, self.tl_url, self.key_tls_pub
                        )

            else:
                raise RecordManagementException(
                    f"Unable to find public key {self.key_tls_pub} while signing data for agent {agent_data['agent_id']}"
                )

        return contents_for_signing

    def base_record_timestamp_create(
        self, record_object: Dict[Any, Any], agent_data: Dict[Any, Any], contents: bytes
    ) -> None:
        """Accesses a Time Stamp Autorhity (TSA) and gets a signed timestamp for a given contents"""
        if self.tsa_url.scheme and contents:
            logger.debug(
                "Obtaining a time stamp for data referring to agent %s from TSA at %s",
                agent_data["agent_id"],
                self.tsa_url._replace(fragment="").geturl(),
            )

            getattr(importlib.import_module(self.st_imp_path + ".tsa_rfc3161"), "record_timestamp_create")(
                record_object, agent_data["agent_id"], contents, self.tsa_url, self.tsa_cert
            )

        else:
            if not self.tsa_url.scheme:
                logger.debug(
                    "No Time Stamp Authority URL specified, will not create a timestamp for  data referring to agent %s",
                    agent_data["agent_id"],
                )
            if not contents:
                logger.debug(
                    "No attributes specified to be signed. Will skip timestamping the signing of data referring to agent %s",
                    agent_data["agent_id"],
                )

    def base_record_timestamp_check(
        self, record_object: Dict[Any, Any], record_identifier: str, contents: bytes
    ) -> None:
        """Accesses a Time Stamp Autorhity (TSA) and checks a signed timestamp for a given contents"""
        if self.tsa_url.scheme and contents:

            logger.debug(
                "Checking the time stamp for data referring to agent %s from TSA at %s",
                record_identifier,
                self.tsa_url._replace(fragment="").geturl(),
            )

            getattr(importlib.import_module(self.st_imp_path + ".tsa_rfc3161"), "record_timestamp_check")(
                record_object, record_identifier, contents, self.tsa_url, self.tsa_cert
            )

    def base_record_signature_check(
        self, record_object: Dict[Any, Any], agent_data: Dict[Any, Any]
    ) -> Optional[Dict[str, Any]]:
        """Check the signature for contents of a given record"""

        if not "signature" in record_object:
            return None

        self.set_certs_path()

        if not self.key_tls_pub:
            raise RecordManagementException(
                f"Unable to find public key {self.key_tls_pub} while signing data for agent {agent_data['agent_id']}"
            )

        with tempfile.TemporaryDirectory() as _temp_dir_path:

            record_object["temp_dir"] = _temp_dir_path
            record_object["contents_file_path"] = f'{record_object["temp_dir"]}/object.json'
            record_object["signature_file_path"] = f'{record_object["temp_dir"]}/object.json.sig'

            with open(record_object["signature_file_path"], "wb") as fp:
                try:
                    record_object["signature"] = str.encode(record_object["signature"])
                except Exception:
                    pass
                fp.write(base64.decodebytes(record_object["signature"]))

            with open(self.key_tls_pub, "w", encoding="utf-8") as fp:
                fp.write(record_object["signer_pub_key"])

            _contents_to_check = {}
            _contents_to_check["agent"] = record_object["agent"]

            _contents_to_check_bytes = json.dumps(_contents_to_check).encode("utf-8")

            with open(record_object["contents_file_path"], "wb") as fp:
                fp.write(_contents_to_check_bytes)

            if "contents_file_path" in record_object and "signature_file_path" in record_object:
                if self.tl_url.scheme == "http" and self.tl_url.netloc.count("3000"):
                    getattr(importlib.import_module(self.st_imp_path + ".rekor"), "record_signature_check")(
                        record_object, agent_data, self.tl_url, self.key_tls_pub
                    )

        return _contents_to_check

    def only_last_record_wanted(self, start_date: int, end_date: int) -> bool:
        if start_date == self.end_of_times - 1 and end_date == self.end_of_times:
            return True
        return False


class RecordManagementException(Exception):
    pass


def base_build_key_list(registration_record_list: List[Dict[Any, Any]]) -> List[str]:
    """Just assembles a simple list of AIKs used by an agent"""

    aik_list: List[str] = []
    for _entry in registration_record_list:
        if _entry["agent"]["aik_tpm"] not in aik_list:
            logger.debug("New AIK added to the list")
            aik_list.append(_entry["agent"]["aik_tpm"])

    return aik_list


def get_record_mgt_class(store_import: str = "") -> Optional[Any]:
    """Dynamically imports a persistent store backend"""
    if store_import:
        return getattr(importlib.import_module(store_import), "RecordManagement")
    return None
