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
# Copyright 2015 Massachusetts Institute of Technology.
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

echo "Deleting..."
rm -fv .auditing*
rm -fv aik*
rm -fv *cv_persis*
rm -fv *en_persis*
rm -fv owner_pw.txt
rm -fv *pem
rm -fv tmpfs-dev/derived_tci_key
rm -fv tpm_nvram
rm -fv *log_*
rm -fv keylime-dev.log
rm -fv decrypted_payload
rm -fv encrypted_payload
rm -vrf reg_ca
rm -vrf cv_ca
rm -fv *.sqlite
rm -fv tpmdata.json tpmdata.yml
rm -fv current_group.tpm
rm -fv group-*
rm -vrf ca
rm -vrf tmpfs-dev/unzipped
init_tpm_server
tpm_serverd
