import time

import redis

from keylime import keylime_logging
from keylime.cli.options import extract_password
from keylime.da.record import BaseRecordManagement, base_build_key_list

# setup logging
logger = keylime_logging.init_logging("durable_attestation_persistent_store")

# ######################################################
# Durable Attestation record manager with Redis backend
# ######################################################


class RecordManagement(BaseRecordManagement):
    def __init__(self, service):

        BaseRecordManagement.__init__(self, service)

        (
            self.redis_ip,
            self.redis_port,
        ) = self.ps_url.netloc.split(":")

        self.redis_db, self.redis_password, self.redis_prefix = (
            self.ps_url.query.replace("db=", "").replace("password=", "").replace("prefix=", "").split("&")
        )

        self.redis_password = extract_password(self.redis_password)
        self.redis_conn = None

    def redis_connect(self):
        if not self.redis_conn:
            self.redis_conn = redis.Redis(
                host=self.redis_ip, port=self.redis_port, db=self.redis_db, password=self.redis_password
            )

    def redis_multi_version_zadd(self, key, value, score):
        if int(redis.__version__[0]) < 3:
            self.redis_conn.zadd(key, value, score)
        else:
            self.redis_conn.zadd(key, {value: score})

    def agent_list_retrieval(self, record_prefix="auto", service="auto"):

        self.redis_connect()

        agent_list = []

        if record_prefix == "auto":
            record_prefix = self.redis_prefix

        record_prefix = f"{record_prefix}_{self.get_record_type(service)}"

        logger.debug(
            "Extracting the UUIDs of all agents with entries with prefix %s from redis persistent store", record_prefix
        )
        for entry in self.redis_conn.keys(pattern=record_prefix + "*"):
            agent_uuid = entry.decode("utf-8").replace(f"{record_prefix}_", "")
            if agent_uuid not in agent_list:
                agent_list.append(agent_uuid)
        return agent_list

    def _bulk_record_retrieval(self, record_identifier, start_date=0, end_date=-1):

        logger.debug("Extracting all records for record_identifier %s from redis persistent store", record_identifier)

        self.redis_connect()

        record_list = []

        if self.only_last_record_wanted(start_date, end_date):
            encoded_record_object_list = self.redis_conn.zrevrange(record_identifier, 0, 0)
        else:
            encoded_record_object_list = self.redis_conn.zrange(record_identifier, start_date, end_date)

        for encoded_record_object in encoded_record_object_list:

            decoded_record_object = self.record_deserialize(encoded_record_object)

            self.record_signature_check(decoded_record_object, record_identifier)

            record_list.append(decoded_record_object)

        return record_list

    def build_key_list(self, agent_identifier, service="auto"):

        registration_record_identifier = f"{self.redis_prefix}_{self.get_record_type(service)}_{agent_identifier}"

        registration_record_list = self._bulk_record_retrieval(registration_record_identifier)

        return base_build_key_list(registration_record_list)

    def record_read(self, agent_identifier, start_date, end_date, service="auto"):

        attestation_record_identifier = f"{self.redis_prefix}_{self.get_record_type(service)}_{agent_identifier}"

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

        key = f'{self.redis_prefix}_{self.get_record_type(service)}_{agent_data["agent_id"]}'

        self.redis_connect()

        logger.debug(
            "Recording new %s entry for agent %s on redis persistent store",
            self.get_record_type(service),
            agent_data["agent_id"],
        )
        self.redis_multi_version_zadd(
            key, self.base_record_create(record_object, agent_data, attestation_data, ima_policy_data), int(time.time())
        )
