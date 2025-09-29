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

# If CONTAINER_ENGINE is not set by the user, try to autodetect it.
if [ -z "$CONTAINER_ENGINE" ]; then
    if command -v docker &> /dev/null; then
        CONTAINER_ENGINE="docker"
    elif command -v podman &> /dev/null; then
        CONTAINER_ENGINE="podman"
    else
        echo "ERROR: No container engine specified, and could not find 'docker' or 'podman' in PATH." >&2
        exit 1
    fi
fi

FEDORA_IMAGE="${REGISTRY}/fedora/fedora"
QUERY_RESULT="$(skopeo inspect docker://${FEDORA_IMAGE}:latest)"
ret=$?
if [[ $ret -eq 127 ]]; then
    echo "Failed to get latest Fedora image digest. Please install skopeo."
    exit 127
elif [[ $ret -ne 0 ]]; then
    echo "Failed to get latest Fedora image digest."
    exit $ret
else
    FEDORA_DIGEST="$(jq '.Digest' <<<"$QUERY_RESULT")"
fi

# Prepare base image Dockerfile
sed -i "s#\(FROM \)[^ ]*#\1${FEDORA_IMAGE}@${FEDORA_DIGEST}#" base/Dockerfile.in
sed "s#_version_#${VERSION}#" base/Dockerfile.in > base/Dockerfile

# Prepare other components Dockerfile
./generate-files.sh ${VERSION}

# Build images
for part in base registrar verifier tenant; do
  ${CONTAINER_ENGINE} buildx build -t keylime_${part}:${VERSION} -f "${part}/Dockerfile" --security-opt label=disable --progress plain ${@:3} "$KEYLIME_DIR"
  rm -f ${part}/Dockerfile
done
