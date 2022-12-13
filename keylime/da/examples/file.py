import os
import time

from keylime import keylime_logging
from keylime.da.record import BaseRecordManagement, base_build_key_list

# setup logging
logger = keylime_logging.init_logging("durable_attestation_persistent_store")

# ######################################################
# Durable Attestation record manager with "plain file" backend
# ######################################################


class RecordManagement(BaseRecordManagement):
    def __init__(self, service):

        BaseRecordManagement.__init__(self, service)
        self.rcd_enc = "base64"
        self.file_path = self.ps_url.path
        self.file_prefix = self.ps_url.query.replace("prefix=", "")
        self.line_sep = b"\n----\n"
        self.ts_sep = b"--"

        os.makedirs(self.file_path, exist_ok=True)

    def agent_list_retrieval(self, record_prefix="auto", service="auto"):

        if record_prefix == "auto":
            record_prefix = self.file_prefix

        agent_list = []

        record_prefix = f"{record_prefix}_{self.get_record_type(service)}"
        logger.debug(
            "Extracting the UUIDs of all agents with entries with prefix %s from filesystem persistent store",
            record_prefix,
        )
        for entry in next(os.walk(self.file_path), (None, None, []))[2]:
            if record_prefix in entry:
                agent_uuid = entry.replace(f"{record_prefix}_", "").replace(f".{self.rcd_fmt}", "")
                if agent_uuid not in agent_list:
                    agent_list.append(agent_uuid)

        return agent_list

    def _bulk_record_retrieval(self, record_identifier, start_date=0, end_date="auto"):

        logger.debug(
            "Extracting all records for record_identifier %s from filesystem persistent store", record_identifier
        )

        if f"{end_date}" == "auto":
            end_date = self.end_of_times

        record_list = []

        with open(record_identifier, "rb") as fp:
            if self.only_last_record_wanted(start_date, end_date):
                start_date = 0
                # A simple and unoptimized way to get penultimate line of the
                # file (given the last line is just a separator)
                try:
                    fp.seek(-2, os.SEEK_END)
                    while fp.read(1) != b"\n":
                        fp.seek(-2, os.SEEK_CUR)

                    fp.seek(-2, os.SEEK_CUR)
                    while fp.read(1) != b"\n":
                        fp.seek(-2, os.SEEK_CUR)

                except OSError:
                    fp.seek(0)

            for _line in fp:
                if b"\n" + _line != self.line_sep:

                    internal_timestamp, encoded_record_object = _line.split(self.ts_sep)

                    decoded_record_object = self.record_deserialize(encoded_record_object)

                    internal_timestamp = int(internal_timestamp)
                    if start_date <= internal_timestamp <= end_date:

                        self.record_signature_check(decoded_record_object, record_identifier)

                        record_list.append(decoded_record_object)

        return record_list

    def build_key_list(self, agent_identifier, service="auto"):

        registration_record_identifier = (
            f"{self.file_path}/{self.file_prefix}_{self.get_record_type(service)}_{agent_identifier}.{self.rcd_fmt}"
        )

        registration_record_list = self._bulk_record_retrieval(registration_record_identifier)

        return base_build_key_list(registration_record_list)

    def record_read(self, agent_identifier, start_date, end_date, service="auto"):

        attestation_record_identifier = (
            f"{self.file_path}/{self.file_prefix}_{self.get_record_type(service)}_{agent_identifier}.{self.rcd_fmt}"
        )

        attestation_record_list = self._bulk_record_retrieval(attestation_record_identifier, start_date, end_date)

        self.base_record_read(attestation_record_list)

        return attestation_record_list

    def record_signature_check(self, record_object, record_identifier):

        contents = self.base_record_signature_check(record_object, record_identifier)

        self.base_record_timestamp_check(record_object, record_identifier, contents)

    def record_signature_create(
        self, record_object, agent_data, attestation_data, service="auto", signed_attributes="auto"
    ):

        contents = self.base_record_signature_create(
            record_object, agent_data, attestation_data, service, signed_attributes
        )

        self.base_record_timestamp_create(record_object, agent_data, contents)

    def record_create(
        self, agent_data, attestation_data, ima_policy_data=None, service="auto", signed_attributes="auto"
    ):

        record_object = {}

        self.record_signature_create(record_object, agent_data, attestation_data, service, signed_attributes)

        logger.debug(
            "Recording new %s entry for agent %s on filesystem persistent store",
            self.get_record_type(service),
            agent_data["agent_id"],
        )
        with open(
            f'{self.file_path}/{self.file_prefix}_{self.get_record_type(service)}_{agent_data["agent_id"]}.{self.rcd_fmt}',
            "ab",
        ) as fp:
            ts = str(int(time.time())).encode()
            fp.write(
                ts + self.ts_sep + self.base_record_create(record_object, agent_data, attestation_data, ima_policy_data)
            )
            fp.write(self.line_sep)
