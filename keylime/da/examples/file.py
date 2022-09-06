import importlib
import os
import re

from keylime import keylime_logging
from keylime.da.record import BaseRecordManagement

# setup logging
logger = keylime_logging.init_logging("persistent_store")


class RecordManagement(BaseRecordManagement):
    def __init__(self, service):

        BaseRecordManagement.__init__(self, service)
        self.rcd_enc = "base64"
        self.file_path, self.file_prefix = re.split(
            r":|\?|&",
            self.ps_url.replace("file://", "").replace("db=", "").replace("password=", "").replace("prefix=", ""),
        )
        self.line_sep = str.encode("\n----\n")

        self.mkdir_p(self.file_path)

    def agent_list_retrieval(self, agent_list, record_prefix="auto", service="auto"):

        if record_prefix == "auto":
            record_prefix = self.file_prefix

        record_prefix += "_" + service
        logger.debug(
            "Extracting the UUIDs of all agents with entries with prefix %s from filesystem persistent store",
            record_prefix,
        )
        for _entry in next(os.walk(self.file_path), (None, None, []))[2]:
            if service in _entry:
                _agent_uuid = _entry.replace(record_prefix + "_", "").replace("." + self.rcd_fmt, "")
                if _agent_uuid not in agent_list:
                    agent_list.append(_agent_uuid)

    def bulk_record_retrieval(self, record_identifier, record_list):

        logger.debug(
            "Extracting all records for record_identifier %s from filesystem persistent store", record_identifier
        )

        with open(record_identifier, "rb") as fp:
            for _line in fp:
                if b"\n" + _line != self.line_sep:
                    _encoded_record_object = _line

                    _decoded_record_object = self._record_decode(_encoded_record_object)

                    self.record_signature_check(_decoded_record_object, record_identifier)

                    record_list.append(_decoded_record_object)

    def build_key_list(self, agent_identifier, aik_list, service="auto"):

        _registration_record_identifier = (
            self.file_path
            + "/"
            + self.file_prefix
            + "_"
            + self._get_record_type(service)
            + "_"
            + agent_identifier
            + "."
            + self.rcd_fmt
        )

        _registration_record_list = []

        self.bulk_record_retrieval(_registration_record_identifier, _registration_record_list)

        self._build_key_list(_registration_record_list, aik_list)

    def record_read(self, attestation_record_list, agent_identifier, service="auto"):

        _attestation_record_identifier = (
            self.file_path
            + "/"
            + self.file_prefix
            + "_"
            + self._get_record_type(service)
            + "_"
            + agent_identifier
            + "."
            + self.rcd_fmt
        )

        self.bulk_record_retrieval(_attestation_record_identifier, attestation_record_list)

        self._record_read(attestation_record_list)

    def record_signature_check(self, record_object, record_identifier):

        self._record_signature_check(record_object)

        if "contents_file_path" in record_object and "signature_file_path" in record_object:
            if self.tl_url.count("http") and self.tl_url.count("3000"):
                getattr(importlib.import_module(self.st_imp_path + ".rekor"), "record_signature_check")(
                    record_object, record_identifier, self.tl_url, self.cert_tls_pub, self.tmp_d_cl
                )

    def record_signature_create(
        self, record_object, agent_data, attestation_data, service="auto", signed_attributes="auto"
    ):

        self._record_signature_create(record_object, agent_data, attestation_data, service, signed_attributes)

        if "contents_file_path" in record_object and "signature_file_path" in record_object:
            if self.tl_url.count("http") and self.tl_url.count("3000"):
                getattr(importlib.import_module(self.st_imp_path + ".rekor"), "record_signature_create")(
                    record_object, agent_data, self.tl_url, self.cert_tls_pub, self.tmp_d_cl
                )

    def record_create(
        self, agent_data, attestation_data, ima_policy_data=None, service="auto", signed_attributes="auto"
    ):

        record_object = {}

        self.record_signature_create(record_object, agent_data, attestation_data, service, signed_attributes)

        logger.debug(
            "Recording new %s entry for agent %s on filesystem persistent store",
            self._get_record_type(service),
            agent_data["agent_id"],
        )
        with open(
            self.file_path
            + "/"
            + self.file_prefix
            + "_"
            + self._get_record_type(service)
            + "_"
            + agent_data["agent_id"]
            + "."
            + self.rcd_fmt,
            "ab",
        ) as fp:
            fp.write(self._record_create(record_object, agent_data, attestation_data, ima_policy_data))
            fp.write(self.line_sep)
