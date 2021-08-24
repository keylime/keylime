'''
SPDX-License-Identifier: Apache-2.0
Copyright 2017 Massachusetts Institute of Technology.
'''

import gnupg

from keylime import keylime_logging

logger = keylime_logging.init_logging('gpg')

def gpg_verify_filesignature(gpg_key_file, filename, gpg_sig_file, file_description):
    """
       Verify the file signature (gpg_sig_file) using a public GPG (gpg_key_file)
       with the file (filename).
    """
    gpg = gnupg.GPG()
    with open(gpg_key_file, encoding="utf-8") as key_f:
        logger.debug("Importing GPG key %s", gpg_key_file)
        gpg_imported = gpg.import_keys(key_f.read())
        if gpg_imported.count == 1: # pylint: disable=E1101
            logger.debug("GPG key successfully imported")
        else:
            raise Exception(f"Unable to import GPG key: {gpg_key_file}")

    with open(gpg_sig_file, 'rb') as sig_f:
        logger.debug("Comparing %s (%s) against GPG signature (%s)", file_description, filename, gpg_sig_file)
        verified = gpg.verify_file(sig_f, filename)
        if verified:
            logger.debug("%s passed GPG signature verification", file_description.capitalize())
        else:
            raise Exception(f"{file_description.capitalize()} GPG signature verification failed comparing {file_description} ({filename}) against gpg_sig_file ({gpg_sig_file})")
