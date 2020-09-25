#!/bin/bash
set -x

KEYLIME_HOME="${KEYLIME_HOME=:-/root/keylime}"

# Configure swtpm2
cd ${KEYLIME_HOME}/scripts
chmod +x init_tpm_server
chmod +x tpm_serverd
install -c tpm_serverd /usr/local/bin/tpm_serverd
install -c init_tpm_server /usr/local/bin/init_tpm_server
# Server needs to be running, or tpm2-abrmd.service will fail.
/usr/local/bin/tpm_serverd

export TPM2TOOLS_TCTI="tabrmd:bus_name=com.intel.tss2.Tabrmd"
pkill -HUP dbus-daemon

# Configure tpm2-abrmd systemd
# systemd-udev-settle is not needed to run tpm2-tools in container
sed -i 's/^After/#&/' /usr/lib/systemd/system/tpm2-abrmd.service
sed -i 's/^Requires/#&/' /usr/lib/systemd/system/tpm2-abrmd.service
# the tpm device is not needed to run tpm2-tools in container with the
# tpm emulator
sed -i 's/^ConditionPathExists/#&/' /usr/lib/systemd/system/tpm2-abrmd.service
sed -i 's/.*ExecStart.*/ExecStart=\/usr\/sbin\/tpm2-abrmd --tcti=mssim/' /usr/lib/systemd/system/tpm2-abrmd.service
systemctl daemon-reload
systemctl enable tpm2-abrmd
systemctl start tpm2-abrmd
# Check that tpm2-abrmd is actually running as starting it won't report failures
if ! (systemctl -q is-active tpm2-abrmd); then
    echo "tpm2-abrmd failed to start, exiting"
    exit 1
fi

# Run tests
cd ${KEYLIME_HOME}/test
chmod +x ./run_tests.sh
./run_tests.sh -s openssl
