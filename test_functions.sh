#!/bin/bash

AGENT_UUID="d432fbb3-d2f1-4a97-9ef7-75bd81c00000"

# Test get_status
echo "Testing get_status function:"
output=$(docker exec keylime-verifier keylime_tenant -c status -u "${AGENT_UUID}" 2>&1)
status=$(echo "$output" | grep '"operational_state"' | tail -1 | \
    awk -F'"operational_state": "' '{print $2}' | awk -F'"' '{print $1}')
echo "Status: $status"

# Test get_count
echo "Testing get_count function:"
count=$(echo "$output" | grep '"attestation_count"' | tail -1 | \
    awk -F'"attestation_count": ' '{print $2}' | awk -F',' '{print $1}')
echo "Count: $count"

# Test check_containers
echo "Testing check_containers function:"
running=$(docker ps --format "{{.Names}}" | grep -c keylime || echo 0)
echo "Containers: $running"
