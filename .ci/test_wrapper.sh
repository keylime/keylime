#!/bin/bash

tpm_server &
pkill -HUP dbus-daemon
sed -i 's/.*ExecStart.*/ExecStart=\/usr\/sbin\/tpm2-abrmd --tcti=libtss2-tcti-mssim.so/' /usr/lib/systemd/system/tpm2-abrmd.service
systemctl daemon-reload
systemctl enable tpm2-abrmd
systemctl start tpm2-abrmd
export TPM2TOOLS_TCTI="mssim:port=2321"

cd /root/python-keylime/test

chmod +x ./run_tests.sh
./run_tests.sh -s openssl
