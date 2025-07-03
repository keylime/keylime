# Keylime Health Monitor - Quick Reference

## Quick Start
```bash
# Make executable
chmod +x final_monitor.sh

# Check current status
./final_monitor.sh status

# Start monitoring (runs continuously)
./final_monitor.sh monitor

# Restart agent only
./final_monitor.sh restart

# Full system restart
./final_monitor.sh restart-all
```

## Status Indicators
- ✅ **Green**: Healthy, working properly
- ⚠️ **Yellow**: Warning, attention needed
- ❌ **Red**: Error, action required

## What It Monitors
- **Containers**: Ensures all 3 Keylime containers are running
- **Agent Status**: Tracks attestation state (`Get Quote`, `Registered`, etc.)
- **Attestation Progress**: Monitors increasing attestation counts
- **Recovery**: Automatically restarts components when issues detected

## Recovery Strategy
1. **First failure**: Restart agent container and re-register
2. **Second failure**: Try agent restart again
3. **Third+ failure**: Full system restart (all containers)
4. **Missing containers**: Immediate full restart

## Key Files
- **Script**: `final_monitor.sh`
- **Logs**: `monitor.log` 
- **Config**: Uses agent UUID `d432fbb3-d2f1-4a97-9ef7-75bd81c00000`

## Typical Usage Patterns

### Development/Testing
```bash
# Quick health check
./final_monitor.sh status

# Watch logs while testing
tail -f monitor.log
```

### Production
```bash
# Run in background with nohup
nohup ./final_monitor.sh monitor > /dev/null 2>&1 &

# Or better: set up as systemd service (see full documentation)
```

### Troubleshooting
```bash
# Test core functions
./final_monitor.sh test

# Debug mode
bash -x final_monitor.sh status

# Check what containers are running
docker ps | grep keylime
```

## When to Use Each Command

| Situation | Command | Why |
|-----------|---------|-----|
| Regular health check | `status` | Quick overview |
| Agent seems stuck | `restart` | Lighter touch recovery |
| Multiple issues | `restart-all` | Clean slate approach |
| Development work | `monitor` | Continuous oversight |
| Container problems | `restart-all` | Container orchestration reset |

## Expected Healthy Output
```
=== Keylime Monitoring Status ===
Timestamp: Thu Jul  3 12:45:23 UTC 2025
Containers running: 3/3
Agent status: Get Quote
Attestation count: 142

✅ All containers running
✅ Agent is healthy and attesting
```

For complete documentation see: `MONITOR_DOCUMENTATION.md`
