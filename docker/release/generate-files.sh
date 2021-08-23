#!/bin/bash

# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Thore Sommer

# Prepare dockerfiles for build

VERSION=${1:-latest}
SOURCE=${2:-""}

# Docker only allows lower case repositories
SOURCE=$(echo -n ${SOURCE} | tr '[:upper:]' '[:lower:]')
for part in base registrar verifier tenant; do
  echo "Generating ${part}"
  sed "s#_version_#${VERSION}#" "${part}/Dockerfile.in" > ${part}/Dockerfile
  sed -i "s#_source_#${SOURCE}#" ${part}/Dockerfile
done