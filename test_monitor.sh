#!/bin/bash

# Quick test of Keylime monitoring functions

AGENT_UUID="d432fbb3-d2f1-4a97-9ef7-75bd81c00000"

echo "Testing Keylime monitoring..."

echo "1. Testing container status:"
docker ps --format "{{.Names}}" | grep keylime

echo -e "\n2. Testing agent status extraction:"
# Use timeout to prevent hanging
timeout 15 docker exec keylime-verifier keylime_tenant -c status -u "${AGENT_UUID}" 2>&1 | \
    grep '"operational_state"' | tail -1 | \
    sed 's/.*"operational_state": "\([^"]*\)".*/\1/' || echo "TIMEOUT"

echo -e "\n3. Testing attestation count:"
timeout 15 docker exec keylime-verifier keylime_tenant -c status -u "${AGENT_UUID}" 2>&1 | \
    grep '"attestation_count"' | tail -1 | \
    sed 's/.*"attestation_count": \([0-9]*\).*/\1/' || echo "TIMEOUT"

echo -e "\n4. Quick status check:"
echo "Containers running: $(docker ps --format "{{.Names}}" | grep keylime | wc -l)/3"

echo -e "\nTest completed!"
