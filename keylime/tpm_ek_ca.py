import glob
import os

from keylime import config, keylime_logging

logger = keylime_logging.init_logging("tpm_ek_ca")
trusted_certs = {}
tpm_cert_store = config.get("tenant", "tpm_cert_store")


def check_tpm_cert_store():
    if not os.path.isdir(tpm_cert_store):
        logger.error("The directory %s does not exist.", tpm_cert_store)
        raise Exception(f"The directory {tpm_cert_store} does not exist.")

    for fname in os.listdir(tpm_cert_store):
        if fname.endswith(".pem"):
            break
    else:
        logger.error("The directory %s does not contain any .pem files.", tpm_cert_store)
        raise Exception(f"The directory {tpm_cert_store} does not contain " f"any .pem files")


def cert_loader():
    file_list = glob.glob(os.path.join(os.getcwd(), tpm_cert_store + "*.pem"))
    my_trusted_certs = []
    for file_path in file_list:
        with open(file_path, encoding="utf-8") as f_input:
            my_trusted_certs.append(f_input.read())
    return my_trusted_certs
