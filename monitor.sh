#!/bin/bash

# Simple wrapper for the Keylime Health Monitor
# Place this in your keylime directory for easy access

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HEALTH_MONITOR="/home/shubhgupta/keylime_health_monitor.sh"

# Change to the keylime directory
cd "$SCRIPT_DIR"

# Run the health monitor with all arguments
exec "$HEALTH_MONITOR" "$@"
