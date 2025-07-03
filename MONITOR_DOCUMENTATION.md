# Keylime Attestation Health Monitor Documentation

## Overview

The `final_monitor.sh` script is an automated health monitoring and recovery system for Keylime attestation infrastructure running in Docker containers. It provides continuous monitoring, health assessment, and automatic recovery mechanisms for Keylime agent attestation failures.

## Features

- **Real-time Monitoring**: Continuously monitors agent attestation status and container health
- **Automatic Recovery**: Intelligently restarts components when issues are detected
- **Graduated Response**: Escalates from agent restart to full system restart based on failure severity
- **Comprehensive Logging**: Detailed logging with timestamps for troubleshooting
- **Status Reporting**: Clear health status reporting with visual indicators
- **Container Management**: Monitors and manages Docker container lifecycle

## Architecture

The script monitors a Keylime deployment with the following components:
- **keylime-agent**: The TPM-enabled agent container (Rust-based)
- **keylime-verifier**: The Python-based verifier service
- **keylime-registrar**: The agent registration service

## Commands

### Basic Usage
```bash
./final_monitor.sh [command]
```

### Available Commands

#### `monitor` (default)
Starts continuous monitoring mode. The script will:
- Check container health every 30 seconds
- Monitor attestation progress
- Automatically restart components when issues are detected
- Log all activities to `monitor.log`

**Example:**
```bash
./final_monitor.sh monitor
# or simply
./final_monitor.sh
```

#### `status`
Displays current system health status with visual indicators.

**Example Output:**
```
=== Keylime Monitoring Status ===
Timestamp: Thu Jul  3 12:45:23 UTC 2025
Containers running: 3/3
Agent status: Get Quote
Attestation count: 142

✅ All containers running
✅ Agent is healthy and attesting
```

**Status Indicators:**
- ✅ Healthy/Good status
- ⚠️ Warning/Attention needed
- ❌ Error/Problem detected

#### `restart`
Performs agent-only restart. This includes:
1. Restarting the keylime-agent container
2. Removing agent from verifier
3. Re-registering agent with verifier

**Example:**
```bash
./final_monitor.sh restart
```

#### `restart-all`
Performs full system restart. This includes:
1. Stopping all containers with cleanup
2. Starting all services
3. Re-registering the agent

**Example:**
```bash
./final_monitor.sh restart-all
```

#### `test`
Tests core monitoring functions and displays results.

**Example:**
```bash
./final_monitor.sh test
```

## Health Assessment Logic

### Container Health
- Monitors that all 3 Keylime containers are running
- Triggers full restart if containers are missing

### Agent Status Evaluation

| Status | Healthy Condition | Action |
|--------|------------------|---------|
| `Get Quote` | Attestation count increasing | ✅ Healthy |
| `Start` | Attestation count increasing | ✅ Healthy |
| `Tenant Start` | Attestation count increasing | ✅ Healthy |
| `Registered` | Has attestations (count > 0) | ✅ Healthy |
| `Invalid Quote` | Any condition | ❌ Restart needed |
| `Failed` | Any condition | ❌ Restart needed |
| Other | Any condition | ⚠️ Investigation needed |

### Recovery Strategy

The script uses a graduated response approach:

1. **First Issue**: Agent restart (up to 2 attempts)
2. **Persistent Issues**: Full system restart
3. **Container Issues**: Immediate full restart

### Stale Attestation Detection
- Tracks attestation count progression
- Flags as stale if count doesn't increase for 3+ monitoring cycles
- Triggers recovery even if status appears healthy

## Configuration

### Environment Variables
```bash
AGENT_UUID="d432fbb3-d2f1-4a97-9ef7-75bd81c00000"  # Target agent UUID
LOGFILE="/home/shubhgupta/keylime/monitor.log"       # Log file location
```

### Timing Parameters
- **Monitoring Interval**: 30 seconds between health checks
- **Agent Restart Wait**: 15 seconds after container restart
- **Registration Delay**: 5 seconds between delete/add operations
- **Full Restart Wait**: 30 seconds for service initialization

## Logging

### Log Location
All activities are logged to: `/home/shubhgupta/keylime/monitor.log`

### Log Format
```
YYYY-MM-DD HH:MM:SS: [message]
```

### Key Log Events
- Monitoring start/stop
- Health status changes
- Recovery actions initiated
- Success/failure of restart operations
- Container status changes

### Sample Log Entries
```
2025-07-03 12:45:00: Starting Keylime attestation monitoring...
2025-07-03 12:45:30: Status: Get Quote, Attestations: 142
2025-07-03 12:46:00: ✅ Healthy - attestations progressing (143 total)
2025-07-03 12:47:30: Health issue detected (failure #1)
2025-07-03 12:47:30: Attempting agent restart...
2025-07-03 12:47:50: Agent restart successful
```

## Dependencies

### Required Commands
- `docker` - Container management
- `docker-compose` or `docker compose` - Multi-container orchestration
- Standard shell utilities (`awk`, `grep`, `cut`)

### Required Containers
The script expects these containers to be defined in docker-compose.yml:
- `keylime-agent`
- `keylime-verifier` 
- `keylime-registrar`

## Troubleshooting

### Common Issues

#### Script Not Executing
```bash
# Make sure script is executable
chmod +x final_monitor.sh

# Check for syntax errors
bash -n final_monitor.sh
```

#### No Output from Status Commands
- Verify containers are running: `docker ps`
- Check if verifier is accessible: `docker exec keylime-verifier keylime_tenant --help`
- Verify agent UUID matches registered agent

#### Continuous Restart Loops
- Check container logs: `docker logs keylime-agent`
- Verify TPM state is clean
- Check agent configuration files
- Review docker-compose.yml network settings

#### Monitoring Stops Unexpectedly
- Check monitor.log for error messages
- Verify Docker daemon is running
- Check system resources (disk space, memory)

### Debug Mode
Run with bash debugging for detailed execution trace:
```bash
bash -x final_monitor.sh status
```

### Manual Testing
Test individual components:
```bash
# Test container detection
docker ps --format "{{.Names}}" | grep keylime

# Test agent status
docker exec keylime-verifier keylime_tenant -c status -u "d432fbb3-d2f1-4a97-9ef7-75bd81c00000"

# Test agent registration
docker exec keylime-verifier keylime_tenant -c add -t keylime-agent -u "d432fbb3-d2f1-4a97-9ef7-75bd81c00000"
```

## Best Practices

### Production Deployment
1. **Run as Systemd Service**: Create a systemd unit for automatic startup
2. **Log Rotation**: Configure logrotate for monitor.log
3. **Monitoring Integration**: Integrate with external monitoring systems
4. **Resource Limits**: Set appropriate container resource limits
5. **Backup Strategy**: Regular backup of agent configurations and keys

### Security Considerations
1. **File Permissions**: Restrict script and log file permissions
2. **Container Security**: Follow Docker security best practices
3. **Network Security**: Secure inter-container communication
4. **Audit Logging**: Enable comprehensive audit logging

### Performance Optimization
1. **Monitoring Frequency**: Adjust monitoring interval based on requirements
2. **Log Management**: Regular log cleanup and rotation
3. **Resource Monitoring**: Monitor system resources during operation

## Integration Examples

### Systemd Service
```ini
[Unit]
Description=Keylime Attestation Monitor
After=docker.service
Requires=docker.service

[Service]
Type=simple
User=keylime
ExecStart=/home/shubhgupta/keylime/final_monitor.sh monitor
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

### Cron Health Check
```bash
# Run status check every 5 minutes and alert on failure
*/5 * * * * /home/shubhgupta/keylime/final_monitor.sh status || /usr/bin/mail -s "Keylime Health Alert" admin@example.com
```

### Prometheus Metrics
The script can be extended to export metrics for Prometheus monitoring by adding metric endpoints to the status function.

## Version History

- **v1.0**: Initial release with basic monitoring and restart capabilities
- **Current**: Enhanced logging, graduated recovery, and stale detection

## Support

For issues related to:
- **Keylime Core**: See Keylime project documentation
- **Docker Issues**: Check Docker and docker-compose documentation  
- **TPM Problems**: Consult TPM and tpm2-tools documentation
- **Monitor Script**: Review logs and use debug mode for troubleshooting
