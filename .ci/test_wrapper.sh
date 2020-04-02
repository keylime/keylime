#!/bin/bash

KEYLIME_HOME=/root/keylime

# Configure swtpm2
cd ${KEYLIME_HOME}/swtpm2_scripts
chmod +x init_tpm_server
chmod +x tpm_serverd
install -c tpm_serverd /usr/local/bin/tpm_serverd
install -c init_tpm_server /usr/local/bin/init_tpm_server
/usr/local/bin/tpm_serverd

export TPM2TOOLS_TCTI="tabrmd:bus_name=com.intel.tss2.Tabrmd"
pkill -HUP dbus-daemon

# Run tests
cd ${KEYLIME_HOME}/test
chmod +x ./run_tests.sh
./run_tests.sh -s openssl
