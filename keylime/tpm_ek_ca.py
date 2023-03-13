import glob
import os
from typing import Dict

from keylime import keylime_logging

logger = keylime_logging.init_logging("tpm_ek_ca")


def cert_loader(tpm_cert_store: str) -> Dict[str, str]:
    file_list = glob.glob(os.path.join(tpm_cert_store, "*.pem"))
    my_trusted_certs = {}
    for file_path in file_list:
        with open(file_path, encoding="utf-8") as f_input:
            my_trusted_certs[file_path] = f_input.read()
    return my_trusted_certs
