import time

import sqlalchemy
import sqlalchemy.ext.declarative

from keylime import keylime_logging
from keylime.da.record import BaseRecordManagement, base_build_key_list

logger = keylime_logging.init_logging("durable_attestation_persistent_store")

# ######################################################
# sqlalchemy table descriptions
# ######################################################

TableBase = sqlalchemy.ext.declarative.declarative_base()


class AttestationRecord(TableBase):
    __tablename__ = "AttestationRecord"
    time = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
    agentid = sqlalchemy.Column(sqlalchemy.String(128), primary_key=True)
    record = sqlalchemy.Column(sqlalchemy.LargeBinary(length=(2**32) - 1))


class RegistrationRecord(TableBase):
    __tablename__ = "RegistrationRecord"
    time = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
    agentid = sqlalchemy.Column(sqlalchemy.String(128), primary_key=True)
    record = sqlalchemy.Column(sqlalchemy.LargeBinary(length=(2**32) - 1))


def type2table(recordtype):
    if "registration" in recordtype:
        return RegistrationRecord
    return AttestationRecord


# ######################################################
# Durable Attestation record manager with sqlalchemy backend
# ######################################################


class RecordManagement(BaseRecordManagement):
    def __init__(self, service):
        BaseRecordManagement.__init__(self, service)

        self.engine = sqlalchemy.create_engine(self.ps_url._replace(fragment="").geturl(), pool_recycle=1800)
        sm = sqlalchemy.orm.sessionmaker()
        self.session = sqlalchemy.orm.scoped_session(sm)
        self.session.configure(bind=self.engine)
        TableBase.metadata.create_all(self.engine)

    def agent_list_retrieval(self, record_prefix="auto", service="auto"):

        if record_prefix == "auto":
            record_prefix = ""

        agent_list = []

        recordtype = self.get_record_type(service)
        tbl = type2table(recordtype)
        for agentid in self.session.query(tbl.agentid).distinct():  # pylint: disable=no-member
            agent_list.append(agentid[0])

        return agent_list

    def record_create(
        self, agent_data, attestation_data, ima_policy_data=None, service="auto", signed_attributes="auto"
    ):

        agentid = agent_data["agent_id"]
        recordtime = str(int(time.time()))
        recordtype = self.get_record_type(service)

        # create the record, and sign it.
        record_object = {}
        self.record_signature_create(record_object, agent_data, attestation_data, service, signed_attributes)
        rcrd = self.base_record_create(record_object, agent_data, attestation_data, ima_policy_data)

        d = {"time": recordtime, "agentid": agentid, "record": rcrd}

        try:
            self.session.add((type2table(recordtype))(**d))  # pylint: disable=no-member
            self.session.commit()  # pylint: disable=no-member
        except Exception as e:
            logger.error("Failed to create attestation record: %s", e)

    def record_signature_create(
        self, record_object, agent_data, attestation_data, service="auto", signed_attributes="auto"
    ):

        contents = self.base_record_signature_create(
            record_object, agent_data, attestation_data, service, signed_attributes
        )

        self.base_record_timestamp_create(record_object, agent_data, contents)

    def _bulk_record_retrieval(self, record_identifier, start_date=0, end_date="auto", service="auto"):
        recordtype = self.get_record_type(service)
        tbl = type2table(recordtype)
        record_list = []

        if f"{end_date}" == "auto":
            end_date = self.end_of_times

        if self.only_last_record_wanted(start_date, end_date):
            attestion_record_rows = (
                self.session.query(tbl)  # pylint: disable=no-member
                .filter(tbl.agentid == record_identifier)
                .order_by(sqlalchemy.desc(tbl.time))
                .limit(1)
            )

        else:
            attestion_record_rows = self.session.query(tbl).filter(  # pylint: disable=no-member
                tbl.agentid == record_identifier
            )

        for row in attestion_record_rows:
            decoded_record_object = self.record_deserialize(row.record)
            self.record_signature_check(decoded_record_object, record_identifier)
            record_list.append(decoded_record_object)
        return record_list

    def build_key_list(self, agent_identifier, service="auto"):
        record_list = self._bulk_record_retrieval(agent_identifier, service)
        return base_build_key_list(record_list)

    def record_read(self, agent_identifier, start_date, end_date, service="auto"):
        attestation_record_list = self._bulk_record_retrieval(agent_identifier, start_date, end_date, service)

        self.base_record_read(attestation_record_list)

        return attestation_record_list

    def record_signature_check(self, record_object, record_identifier):

        contents = self.base_record_signature_check(record_object, record_identifier)

        self.base_record_timestamp_check(record_object, record_identifier, contents)
