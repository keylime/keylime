#!/bin/sh

################################################################################
# Copyright 2017 Massachusetts Institute of Technology.
# SPDX-License-Identifier: Apache-2.0
################################################################################

if [ "$AGENT_UUID" = "" ]
then
   AGENT_UUID=d432fbb3-d2f1-4a97-9ef7-75bd81c00000
fi

wget --ca-certificate=cacert.crt --post-data '{}' \
     --certificate=$AGENT_UUID-cert.crt \
     --private-key=$AGENT_UUID-private.pem \
     https://localhost:6892/agents/$AGENT_UUID
