#!/bin/bash

################################################################################
# SPDX-License-Identifier: Apache-2.0
# Copyright 2017 Massachusetts Institute of Technology.
################################################################################

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
