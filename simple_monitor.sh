#!/bin/bash

# Simple Keylime Attestation Monitor

AGENT_UUID="d432fbb3-d2f1-4a97-9ef7-75bd81c00000"

# Function to get current status
get_status() {
    local status=$(docker exec keylime-verifier keylime_tenant -c status -u "${AGENT_UUID}" 2>/dev/null | \
        grep '"operational_state"' | tail -1 | \
        sed 's/.*"operational_state": "\([^"]*\)".*/\1/' 2>/dev/null || echo "UNKNOWN")
    echo "$status"
}

# Function to get attestation count
get_count() {
    local count=$(docker exec keylime-verifier keylime_tenant -c status -u "${AGENT_UUID}" 2>/dev/null | \
        grep '"attestation_count"' | tail -1 | \
        sed 's/.*"attestation_count": \([0-9]*\).*/\1/' 2>/dev/null || echo "0")
    echo "$count"
}

# Function to restart agent and re-register
restart_agent() {
    echo "$(date): Restarting agent..."
    docker restart keylime-agent
    sleep 15
    
    echo "$(date): Removing agent from verifier..."
    docker exec keylime-verifier keylime_tenant -c delete -u "${AGENT_UUID}" >/dev/null 2>&1 || true
    sleep 5
    
    echo "$(date): Re-adding agent to verifier..."
    if docker exec keylime-verifier keylime_tenant -c add -t keylime-agent -u "${AGENT_UUID}" >/dev/null 2>&1; then
        echo "$(date): Agent recovery successful"
        return 0
    else
        echo "$(date): Agent recovery failed"
        return 1
    fi
}

# Function to restart everything
restart_all() {
    echo "$(date): Performing full restart..."
    
    # Stop services
    if command -v docker-compose >/dev/null 2>&1; then
        docker-compose down --remove-orphans >/dev/null 2>&1 || true
    else
        docker compose down --remove-orphans >/dev/null 2>&1 || true
    fi
    
    # Start services
    if command -v docker-compose >/dev/null 2>&1; then
        docker-compose up -d >/dev/null 2>&1
    else
        docker compose up -d >/dev/null 2>&1
    fi
    
    sleep 30
    
    # Re-register agent
    docker exec keylime-verifier keylime_tenant -c add -t keylime-agent -u "${AGENT_UUID}" >/dev/null 2>&1 || true
    echo "$(date): Full restart completed"
}

# Main monitoring loop
monitor() {
    echo "$(date): Starting Keylime attestation monitoring..."
    local failures=0
    local last_count=0
    local stale_count=0
    
    while true; do
        # Check containers
        local running=$(docker ps --format "{{.Names}}" | grep keylime | wc -l)
        if [[ "$running" -lt 3 ]]; then
            echo "$(date): Only $running/3 containers running - restarting all"
            restart_all
            failures=0
            sleep 60
            continue
        fi
        
        # Get current status
        local status=$(get_status)
        local count=$(get_count)
        
        echo "$(date): Status: $status, Count: $count"
        
        # Check health
        case "$status" in
            "Get Quote"|"Tenant Start"|"Start")
                if [[ "$count" -gt "$last_count" ]]; then
                    failures=0
                    stale_count=0
                    last_count=$count
                    echo "$(date): ✅ Healthy - attestations progressing"
                else
                    stale_count=$((stale_count + 1))
                    if [[ $stale_count -ge 3 ]]; then
                        echo "$(date): ⚠️  Stale attestations detected"
                        failures=$((failures + 1))
                        stale_count=0
                    fi
                fi
                ;;
            "Registered")
                if [[ "$count" -gt 0 ]]; then
                    failures=0
                    echo "$(date): ✅ Registered and attesting"
                else
                    failures=$((failures + 1))
                    echo "$(date): ⚠️  Registered but no attestations"
                fi
                ;;
            "Invalid Quote"|"Failed")
                failures=$((failures + 1))
                echo "$(date): ❌ Error state: $status"
                ;;
            *)
                failures=$((failures + 1))
                echo "$(date): ⚠️  Unknown state: $status"
                ;;
        esac
        
        # Take action based on failures
        if [[ $failures -ge 1 && $failures -le 2 ]]; then
            echo "$(date): Attempting agent restart (failure $failures)"
            restart_agent
        elif [[ $failures -ge 3 ]]; then
            echo "$(date): Multiple failures - performing full restart"
            restart_all
            failures=0
        fi
        
        sleep 30
    done
}

# Handle command line arguments
case "${1:-monitor}" in
    "monitor")
        monitor
        ;;
    "status")
        status=$(get_status)
        count=$(get_count)
        running=$(docker ps --format "{{.Names}}" | grep keylime | wc -l)
        
        echo "=== Keylime Status ==="
        echo "Containers: $running/3 running"
        echo "Agent Status: $status"
        echo "Attestations: $count"
        echo "Timestamp: $(date)"
        
        if [[ "$status" == "Get Quote" || "$status" == "Start" ]] && [[ "$count" -gt 0 ]]; then
            echo "✅ System is healthy"
        else
            echo "⚠️  System needs attention"
        fi
        ;;
    "restart")
        restart_agent
        ;;
    "restart-all")
        restart_all
        ;;
    *)
        cat << EOF
Usage: $0 [COMMAND]

Commands:
    monitor       Start continuous monitoring (default)
    status        Show current status
    restart       Restart agent only
    restart-all   Restart all services

Environment:
    AGENT_UUID    Agent UUID (default: $AGENT_UUID)
EOF
        ;;
esac
