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
# Copyright 2017 Massachusetts Institute of Technology.
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

# don't do this every boot
#echo "resetting TPM"
#init_tpm_server 

echo "starting TPM emulator"
tpm_serverd 

if [[ -n "$(command -v createek)" ]]; then
    echo "Touching prerequisite TPM 1.2 binaries"
    
    createek -h
    getpubek -h
    takeown -h
    identity -h
    getpubkey -h
    listkeys -h
    loadkey -h
    activateidentity -h
    getcapability -h
    nv_definespace -h
    nv_writevalue -h
    nv_readvalue -h
    pcrreset -h
    extend -h
    deepquote -h
    tpmquote -h
    getrandom -h
    flushspecific -h
elif [[ -n "$(command -v tpm2_createek)" ]]; then
    echo "Touching prerequisite TPM 2.0 binaries"
    
    tpm2_createek -h
    tpm2_readpublic -h
    tpm2_changeauth -h
    tpm2_createak -h
    tpm2_activatecredential -h
    tpm2_getcap -h
    tpm2_nvdefine
    tpm2_nvwrite -h
    tpm2_nvread -h
    tpm2_pcrreset -h
    tpm2_pcrextend -h
    tpm2_deluxequote -h
    tpm2_getrandom -h
    tpm2_evictcontrol -h
    tpm2_nvrelease -h
fi

export TPM2TOOLS_TCTI="mssim:port=2321"
echo "starting IMA stub"
pkill -f keylime_ima_emulator
keylime_ima_emulator
