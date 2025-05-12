#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Thore Sommer

# Prepare dockerfiles for build

VERSION=${1:-latest}
SOURCE=${2:-"keylime_base:latest"}
DIGEST=${3:-""}

# Generate Dockerfiles for each component
for part in registrar verifier tenant; do
  echo "Generating ${part}"
  sed "s#_version_#${VERSION}#" "${part}/Dockerfile.in" > ${part}/Dockerfile
  
  # Replace the _source_keylime_base_digest_ placeholder with the full image reference
  if [ -n "$DIGEST" ]; then
    sed -i "s#_source_keylime_base_digest_#${SOURCE}@${DIGEST}#" ${part}/Dockerfile
  else
    sed -i "s#_source_keylime_base_digest_#${SOURCE}#" ${part}/Dockerfile
  fi
done