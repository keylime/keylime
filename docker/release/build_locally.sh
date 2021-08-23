#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Thore Sommer

# Build Docker container locally

VERSION=${1:-latest}
KEYLIME_DIR=${2:-"../../"}

./generate-files.sh ${VERSION}
for part in base registrar verifier tenant; do
  docker buildx build -t keylime_${part} -f ${part}/Dockerfile $KEYLIME_DIR
  rm -f ${part}/Dockerfile
done