import importlib
import os
import re
import time

import redis

from keylime import keylime_logging
from keylime.da.record import BaseRecordManagement

# setup logging
logger = keylime_logging.init_logging("persistent_store")


class RecordManagement(BaseRecordManagement):
    def __init__(self, service):

        BaseRecordManagement.__init__(self, service)

        self.redis_ip, self.redis_port, self.redis_db, self.redis_password, self.redis_prefix = re.split(
            r":|\?|&",
            self.ps_url.replace("redis://", "").replace("db=", "").replace("password=", "").replace("prefix=", ""),
        )

        self.redis_password = self.redis_password.replace("~", os.environ["HOME"])
        self.redis_conn = None

    def redis_connect(self):
        """
        TBD
        """
        if not self.redis_conn:
            if os.path.exists(self.redis_password):

                with open(self.redis_password, encoding="utf-8") as fp:
                    self.redis_password = fp.read().strip()

            self.redis_conn = redis.Redis(
                host=self.redis_ip, port=self.redis_port, db=self.redis_db, password=self.redis_password
            )

    def redis_multi_version_zadd(self, key, value, score):
        """
        TBD
        """
        if int(redis.__version__[0]) < 3:
            self.redis_conn.zadd(key, value, score)
        else:
            self.redis_conn.zadd(key, {value: score})

    def agent_list_retrieval(self, agent_list, record_prefix="auto", service="auto"):

        self.redis_connect()

        if record_prefix == "auto":
            record_prefix = self.redis_prefix

        record_prefix += "_" + service
        logger.debug(
            "Extracting the UUIDs of all agents with entries with prefix %s from redis persistent store", record_prefix
        )
        for _entry in self.redis_conn.keys(pattern=record_prefix + "*"):
            _agent_uuid = _entry.decode("utf-8").replace(record_prefix + "_", "")
            if _agent_uuid not in agent_list:
                agent_list.append(_agent_uuid)

    def bulk_record_retrieval(self, record_identifier, record_list):

        logger.debug("Extracting all records for record_identifier %s from redis persistent store", record_identifier)

        self.redis_connect()

        for _encoded_record_object in self.redis_conn.zrange(record_identifier, 0, -1):

            _decoded_record_object = self._record_decode(_encoded_record_object)

            self.record_signature_check(_decoded_record_object, record_identifier)

            record_list.append(_decoded_record_object)

    def build_key_list(self, agent_identifier, aik_list, service="auto"):

        _registration_record_identifier = (
            self.redis_prefix + "_" + self._get_record_type(service) + "_" + agent_identifier
        )

        _registration_record_list = []

        self.bulk_record_retrieval(_registration_record_identifier, _registration_record_list)

        self._build_key_list(_registration_record_list, aik_list)

    def record_read(self, attestation_record_list, agent_identifier, service="auto"):

        _attestation_record_identifier = (
            self.redis_prefix + "_" + self._get_record_type(service) + "_" + agent_identifier
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

        _key = self.redis_prefix + "_" + self._get_record_type(service) + "_" + agent_data["agent_id"]

        self.redis_connect()

        logger.debug(
            "Recording new %s entry for agent %s on redis persistent store",
            self._get_record_type(service),
            agent_data["agent_id"],
        )
        self.redis_multi_version_zadd(
            _key, self._record_create(record_object, agent_data, attestation_data, ima_policy_data), int(time.time())
        )
