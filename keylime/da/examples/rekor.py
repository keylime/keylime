from keylime import keylime_logging
from keylime.cmd_exec import run

# setup logging
logger = keylime_logging.init_logging("durable_attestation_transparency_log")


def record_signature_create(record_object, agent_data, ts_url, cert_tls_pub):
    logger.debug("Uploading signature entry for data referring to agent %s on rekor", agent_data["agent_id"])
    command = [
        "rekor-cli",
        "upload",
        "--artifact",
        record_object["contents_file_path"],
        "--rekor_server",
        ts_url._replace(fragment="").geturl(),
        "--signature",
        record_object["signature_file_path"],
        "--pki-format",
        "x509",
        "--public-key",
        cert_tls_pub,
    ]
    run(cmd=command)


def record_signature_check(record_object, record_identifier, ts_url, cert_tls_pub):
    logger.debug("Uploading signature entry for data referring to agent %s on rekor", record_identifier)
    command = [
        "rekor-cli",
        "verify",
        "--artifact",
        record_object["contents_file_path"],
        "--rekor_server",
        ts_url._replace(fragment="").geturl(),
        "--signature",
        record_object["signature_file_path"],
        "--pki-format",
        "x509",
        "--public-key",
        cert_tls_pub,
    ]
    run(cmd=command)
