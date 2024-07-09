#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Thore Sommer

# Build Docker container locally

VERSION=${1:-latest}
KEYLIME_DIR=${2:-"../../"}

if [ -z "${REGISTRY}" ]; then
    REGISTRY="quay.io"
fi

if [ -z "${IMAGE_BASE}" ]; then
    IMAGE_BASE="${REGISTRY}/keylime"
fi

./generate-files.sh ${VERSION}
for part in base registrar verifier tenant; do
  docker buildx build -t keylime_${part}:${VERSION} -f "${part}/Dockerfile" --security-opt label=disable --progress plain ${@:3} "$KEYLIME_DIR"
  rm -f ${part}/Dockerfile
done
