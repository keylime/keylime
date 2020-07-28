#!/bin/sh

################################################################################
# Copyright 2017 Massachusetts Institute of Technology.
# SPDX-License-Identifier: Apache-2.0
################################################################################

if [ "$AGENT_UUID" = "" ]
then
   AGENT_UUID=D432FBB3-D2F1-4A97-9EF7-75BD81C00000
fi

wget --ca-certificate=cacert.crt --post-data '{}' \
     --certificate=$AGENT_UUID-cert.crt \
     --private-key=$AGENT_UUID-private.pem \
     https://localhost:6892/agents/$AGENT_UUID
