#!/usr/bin/env bash

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


# Make sure our children don't get loose
function finish() {
    echo "*** Killing all jobs"
    pkill -9 -P $$
    sleep 2
#    kill -9 $(jobs -p)
#    kill -9 $(jobs -rp)
#    wait $(jobs -rp) 2>/dev/null
}
trap finish EXIT

PUBEKBIN="$(realpath $(dirname ${0})/llsrc-vtpm-host0_pubek.bin)"
PUBEKPEM="$(realpath $(dirname ${0})/llsrc-vtpm-host0_pubek.pem)"
KEYLIME="$(realpath $(dirname ${0})/../keylime)"
TESTDIR="$(realpath $(dirname ${0})/test_register)"

function test_vtpmmgr() {
    # Test that everything is fine with basic vtpm manager operations
    echo "*** Testing basic vtpm manager operations ..."
    "${KEYLIME}/vtpm_manager.py" group-del 1
    "${KEYLIME}/vtpm_manager.py" group-add "$PUBEKBIN"
    "${KEYLIME}/vtpm_manager.py" group-del 1


    # Run the built-in test register
    echo "*** Running vtpm manager activation test ..."
    "${KEYLIME}/vtpm_manager.py" test
}

function test_keylime() {
    # Test vtpm-only portion of keylime enrollment
    # /dev/console seems to have permissions issues on my system
    sed -i 's|/dev/console|/dev/stdout|' "${KEYLIME}/../keylime.conf"

    echo "*** Starting services "
    python "${KEYLIME}/registrar.py" 2>&1 | tee registrar.log &
    python "${KEYLIME}/cloud_verifier.py" 2>&1 | tee cloud_verifier.log  &
    sleep 5

    echo "*** Starting provider_regist{er,rar} ..."
    python "${KEYLIME}/provider_registrar.py" 2>&1 | tee provider_registrar.log &
    python "${KEYLIME}/provider_register.py" "${PUBEKPEM}" 2>&1 | tee provider_register.log
}

function init_tpm() {
    local OWNEDSTAMP="/tmp/vtpm-owned-stamp"

    # The following command needs to be run only after restarts
    if [ -d $OWNEDSTAMP ]; then
	return
    else
	mkdir -p $OWNEDSTAMP
	rm -f aik.key
	echo "*** Initializing TPM ";
	python "${KEYLIME}/tpm_initialize.py"
	cp pubek.pem srk.pem owner_pw.txt /tmp/vtpm-owned-stamp/
	echo "*** TPM Initialized with owner PW: $(cat owner_pw.txt)"
    fi

}

# Move to a tmp dir so we vomit group AIK files everywhere
mkdir -p "$TESTDIR"
cp "$PUBEKBIN" "$PUBEKPEM" "$TESTDIR"
cd "$TESTDIR"
rm -f provider_register.log

#init_tpm

#rm -f owner_pw.txt srk.pem pubek.pem
#test_vtpmmgr
test_keylime

if grep "Registration activated." provider_register.log >/dev/null; then
    echo "*** Succeeded"
else
    echo "*** Failed (could not find 'Registration activated.' in register.log)"
fi

exit 2>/dev/null
