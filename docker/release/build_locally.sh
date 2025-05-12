#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Thore Sommer

# Build Docker container locally

VERSION=${1:-latest}
KEYLIME_DIR=${2:-"../../"}

# Create the component Dockerfiles first using generate-files.sh
./generate-files.sh ${VERSION} "keylime_base:${VERSION}"

# Build the base image
echo "Building base image..."
docker build -t keylime_base:${VERSION} -f "base/Dockerfile" "$KEYLIME_DIR"

# Check if base image was built successfully
if ! docker image inspect keylime_base:${VERSION} &> /dev/null; then
    echo "Failed to build base image keylime_base:${VERSION}"
    exit 1
fi

echo "Base image built successfully: keylime_base:${VERSION}"

# Build registrar
echo "Building registrar image..."
docker build -t keylime_registrar:${VERSION} -f "registrar/Dockerfile" "$KEYLIME_DIR"
if ! docker image inspect keylime_registrar:${VERSION} &> /dev/null; then
    echo "Failed to build registrar image"
    exit 1
fi

# Build verifier 
echo "Building verifier image..."
docker build -t keylime_verifier:${VERSION} -f "verifier/Dockerfile" "$KEYLIME_DIR"
if ! docker image inspect keylime_verifier:${VERSION} &> /dev/null; then
    echo "Failed to build verifier image"
    exit 1
fi

# Build tenant
echo "Building tenant image..."
docker build -t keylime_tenant:${VERSION} -f "tenant/Dockerfile" "$KEYLIME_DIR"
if ! docker image inspect keylime_tenant:${VERSION} &> /dev/null; then
    echo "Failed to build tenant image"
    exit 1
fi

echo "All images built successfully"
echo "You can now run the following containers:"
echo "  - keylime_registrar:${VERSION}"
echo "  - keylime_verifier:${VERSION}"
echo "  - keylime_tenant:${VERSION}"