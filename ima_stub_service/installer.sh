#!/bin/bash
################################################################################
# SPDX-License-Identifier: Apache-2.0
# Copyright 2017 Massachusetts Institute of Technology.
################################################################################

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 1>&2
   exit 1
fi

cp tpm_with_ima.sh /usr/local/bin/
chmod 744 /usr/local/bin/tpm_with_ima.sh

if [[ -n `systemctl 2>&1 > /dev/null` ]]; then
	echo "No systemd on this system, starting TPM emulator service manually"
	/usr/local/bin/tpm_with_ima.sh > /dev/null
else
	# create service
	cp tpm_emulator.service /etc/systemd/system
	chmod 664 /etc/systemd/system/tpm_emulator.service
	systemctl enable tpm_emulator.service
	systemctl start tpm_emulator.service
fi
