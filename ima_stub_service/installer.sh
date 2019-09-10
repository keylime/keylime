#!/bin/bash
##########################################################################################
#
# DISTRIBUTION STATEMENT A. Approved for public release: distribution unlimited.
#
# This material is based upon work supported by the Assistant Secretary of Defense for 
# Research and Engineering under Air Force Contract No. FA8721-05-C-0002 and/or 
# FA8702-15-D-0001. Any opinions, findings, conclusions or recommendations expressed in 
# this material are those of the author(s) and do not necessarily reflect the views of the 
# Assistant Secretary of Defense for Research and Engineering.
#
# Copyright 2016 Massachusetts Institute of Technology.
#
# The software/firmware is provided to you on an As-Is basis
#
# Delivered to the US Government with Unlimited Rights, as defined in DFARS Part 
# 252.227-7013 or 7014 (Feb 2014). Notwithstanding any copyright notice, U.S. Government 
# rights in this work are defined by DFARS 252.227-7013 or DFARS 252.227-7014 as detailed 
# above. Use of this work other than as specifically authorized by the U.S. Government may 
# violate any copyrights that exist in this work.
#
##########################################################################################

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
