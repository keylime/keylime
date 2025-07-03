#!/bin/bash

# Simplified Keylime Attestation Monitor and Recovery Script
# This script monitors attestation health and performs recovery actions

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.yml"
AGENT_UUID="d432fbb3-d2f1-4a97-9ef7-75bd81c00000"
HEALTH_CHECK_INTERVAL=30
LOG_FILE="${SCRIPT_DIR}/keylime_monitor.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Logging function
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${timestamp} [${level}] ${message}" | tee -a "${LOG_FILE}"
}

log_info() { log "${BLUE}INFO${NC}" "$@"; }
log_warn() { log "${YELLOW}WARN${NC}" "$@"; }
log_error() { log "${RED}ERROR${NC}" "$@"; }
log_success() { log "${GREEN}SUCCESS${NC}" "$@"; }

# Get agent status from verifier (last occurrence is from verifier)
get_agent_status() {
    docker exec keylime-verifier keylime_tenant -c status -u "${AGENT_UUID}" 2>&1 | \
        grep '"operational_state"' | tail -1 | \
        sed 's/.*"operational_state": "\([^"]*\)".*/\1/' || echo "UNKNOWN"
}

# Get attestation count from verifier
get_attestation_count() {
    docker exec keylime-verifier keylime_tenant -c status -u "${AGENT_UUID}" 2>&1 | \
        grep '"attestation_count"' | tail -1 | \
        sed 's/.*"attestation_count": \([0-9]*\).*/\1/' || echo "0"
}

# Check if containers are running
check_containers() {
    local containers=("keylime-registrar" "keylime-verifier" "keylime-agent")
    for container in "${containers[@]}"; do
        if ! docker ps --format "{{.Names}}" | grep -q "^${container}$"; then
            log_warn "Container ${container} is not running"
            return 1
        fi
    done
    return 0
}

# Check agent health
check_health() {
    local status=$(get_agent_status)
    local count=$(get_attestation_count)
    
    log_info "Status: ${status}, Attestations: ${count}"
    
    case "$status" in
        "Get Quote"|"Tenant Start"|"Start")
            if [[ "$count" -gt 0 ]]; then
                log_success "Agent is healthy"
                return 0
            else
                log_warn "Agent status good but no attestations"
                return 1
            fi
            ;;
        "Registered")
            log_info "Agent registered, checking attestations..."
            if [[ "$count" -gt 0 ]]; then
                log_success "Agent is working"
                return 0
            else
                log_warn "Agent registered but no attestations yet"
                return 1
            fi
            ;;
        "Invalid Quote"|"Failed")
            log_error "Agent in error state: ${status}"
            return 2
            ;;
        *)
            log_warn "Agent in unknown state: ${status}"
            return 1
            ;;
    esac
}

# Soft recovery - restart agent and re-register
soft_recovery() {
    log_info "Starting soft recovery..."
    
    # Restart agent
    log_info "Restarting agent container..."
    docker restart keylime-agent
    
    # Wait for agent to start
    sleep 15
    
    # Remove agent from verifier
    log_info "Removing agent from verifier..."
    docker exec keylime-verifier keylime_tenant -c delete -u "${AGENT_UUID}" >/dev/null 2>&1 || true
    
    sleep 5
    
    # Re-add agent to verifier
    log_info "Adding agent back to verifier..."
    if docker exec keylime-verifier keylime_tenant -c add -t keylime-agent -u "${AGENT_UUID}" >/dev/null 2>&1; then
        log_success "Soft recovery completed"
        return 0
    else
        log_error "Failed to re-add agent"
        return 1
    fi
}

# Hard recovery - restart everything
hard_recovery() {
    log_info "Starting hard recovery..."
    
    # Stop all containers
    log_info "Stopping containers..."
    if command -v docker-compose >/dev/null 2>&1; then
        docker-compose -f "${COMPOSE_FILE}" down --remove-orphans || true
    else
        docker compose -f "${COMPOSE_FILE}" down --remove-orphans || true
    fi
    
    # Clean networks
    log_info "Cleaning networks..."
    docker network prune -f >/dev/null 2>&1 || true
    
    # Start containers
    log_info "Starting containers..."
    if command -v docker-compose >/dev/null 2>&1; then
        docker-compose -f "${COMPOSE_FILE}" up -d
    else
        docker compose -f "${COMPOSE_FILE}" up -d
    fi
    
    # Wait for services
    log_info "Waiting for services to start..."
    sleep 30
    
    # Add agent to verifier
    log_info "Adding agent to verifier..."
    if docker exec keylime-verifier keylime_tenant -c add -t keylime-agent -u "${AGENT_UUID}" >/dev/null 2>&1; then
        log_success "Hard recovery completed"
        return 0
    else
        log_error "Hard recovery failed"
        return 1
    fi
}

# Monitor function
monitor() {
    log_info "Starting Keylime attestation monitoring..."
    local consecutive_failures=0
    local last_count=0
    local stale_checks=0
    
    while true; do
        # Check if containers are running
        if ! check_containers; then
            log_error "Containers not running, performing hard recovery..."
            if hard_recovery; then
                consecutive_failures=0
                stale_checks=0
            else
                log_error "Hard recovery failed, waiting before retry..."
                sleep 60
            fi
            continue
        fi
        
        # Check health
        local health_result
        health_result=$(check_health; echo $?)
        
        case $health_result in
            0)
                # Healthy - check for stale attestations
                local current_count=$(get_attestation_count)
                if [[ "$current_count" -eq "$last_count" ]]; then
                    stale_checks=$((stale_checks + 1))
                    if [[ $stale_checks -ge 3 ]]; then
                        log_warn "Attestations stale, triggering recovery..."
                        health_result=1
                        stale_checks=0
                    fi
                else
                    stale_checks=0
                    last_count=$current_count
                fi
                consecutive_failures=0
                ;;
            *)
                consecutive_failures=$((consecutive_failures + 1))
                log_warn "Health check failed (${consecutive_failures} consecutive failures)"
                ;;
        esac
        
        # Perform recovery if needed
        if [[ $health_result -ne 0 ]]; then
            if [[ $consecutive_failures -le 2 ]]; then
                log_info "Attempting soft recovery..."
                if soft_recovery; then
                    consecutive_failures=0
                    stale_checks=0
                fi
            else
                log_info "Multiple failures, attempting hard recovery..."
                if hard_recovery; then
                    consecutive_failures=0
                    stale_checks=0
                else
                    log_error "Recovery failed, waiting before retry..."
                    sleep 60
                fi
            fi
        fi
        
        # Wait before next check
        sleep "${HEALTH_CHECK_INTERVAL}"
    done
}

# Show current status
show_status() {
    echo "=== Keylime System Status ==="
    echo "Timestamp: $(date)"
    echo "Agent UUID: ${AGENT_UUID}"
    echo
    
    echo "Container Status:"
    docker ps --format "table {{.Names}}\t{{.Status}}" | grep -E "(keylime|NAMES)"
    echo
    
    local status=$(get_agent_status)
    local count=$(get_attestation_count)
    echo "Agent Status: ${status}"
    echo "Attestation Count: ${count}"
    echo
    
    case "$status" in
        "Get Quote"|"Tenant Start"|"Start")
            echo "✅ Agent is actively being monitored"
            ;;
        "Registered")
            if [[ "$count" -gt 0 ]]; then
                echo "✅ Agent is registered and attesting"
            else
                echo "⚠️  Agent registered but no attestations yet"
            fi
            ;;
        "Invalid Quote"|"Failed")
            echo "❌ Agent has errors - requires attention"
            ;;
        *)
            echo "⚠️  Agent in unknown state"
            ;;
    esac
}

# Main function
main() {
    case "${1:-monitor}" in
        "monitor")
            monitor
            ;;
        "status")
            show_status
            ;;
        "check")
            check_health
            ;;
        "soft")
            soft_recovery
            ;;
        "hard")
            hard_recovery
            ;;
        "help"|"--help")
            cat << EOF
Usage: $0 [COMMAND]

Commands:
    monitor    Start continuous monitoring (default)
    status     Show current system status
    check      Check current health
    soft       Perform soft recovery
    hard       Perform hard recovery
    help       Show this help

Environment Variables:
    AGENT_UUID              Agent UUID (default: ${AGENT_UUID})
    HEALTH_CHECK_INTERVAL   Check interval in seconds (default: ${HEALTH_CHECK_INTERVAL})

Examples:
    $0                 # Start monitoring
    $0 status          # Show current status
    $0 check           # Check health once
    $0 soft            # Perform soft recovery
    $0 hard            # Perform hard recovery
EOF
            ;;
        *)
            echo "Unknown command: $1"
            echo "Use '$0 help' for usage information"
            exit 1
            ;;
    esac
}

# Create log file
mkdir -p "$(dirname "$LOG_FILE")"
touch "$LOG_FILE"

# Run main function
main "$@"
