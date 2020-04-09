#!/bin/bash

KEYLIME_HOME=/root/keylime

# Configure swtpm2
cd ${KEYLIME_HOME}/swtpm2_scripts
chmod +x init_tpm_server
chmod +x tpm_serverd
install -c tpm_serverd /usr/local/bin/tpm_serverd
install -c init_tpm_server /usr/local/bin/init_tpm_server
# Server needs to be running, or tpm2-abrmd.service will fail.
/usr/local/bin/tpm_serverd

export TPM2TOOLS_TCTI="tabrmd:bus_name=com.intel.tss2.Tabrmd"
pkill -HUP dbus-daemon

# Configure tpm2-abrmd systemd
sed -i 's/.*ExecStart.*/ExecStart=\/usr\/sbin\/tpm2-abrmd --tcti=mssim/' /usr/lib/systemd/system/tpm2-abrmd.service
systemctl daemon-reload
systemctl enable tpm2-abrmd
systemctl start tpm2-abrmd

# Run tests
cd ${KEYLIME_HOME}/test
chmod +x ./run_tests.sh
./run_tests.sh -s openssl
