# TPM Attack Analysis for Keylime

## How Keylime Attestation Works

1. **Registration**: Agent registers with Keylime registrar
2. **Activation**: Verifier requests agent activation  
3. **Attestation**: Verifier requests TPM quotes every 30 seconds
4. **Quote**: TPM signs PCR values and nonce with Attestation Key
5. **Validation**: Verifier checks signature, nonce, and PCR values

### Key Protections
- **Nonces**: Random values prevent quote replay
- **Digital Signatures**: TPM signs quotes to prove authenticity
- **PCR Values**: Track system integrity state
- **TPM Counters**: Prevent state rollback
- **Resource Manager**: Controls TPM resource usage

---

## Attack Tree 1: TPM Reset/Replay Attack

## Attack 1: TPM Reset/Replay

### How Normal Attestation Works
1. Verifier sends random nonce to agent
2. Agent gets TPM to create a signed quote with:
   - PCR values (system integrity measurements)
   - Verifier's nonce (proves freshness)
   - TPM's clock info (detects resets)
3. Agent sends signed quote back to verifier
4. Verifier checks signature and values match expected policy

### Attack Goal
Make a compromised system appear clean (or vice versa) by manipulating TPM state

### Simplified Attack Tree

```
Goal: Fake Attestation Results
├── Replay Old "Clean" Quotes
│   ├── Intercept and store valid quotes
│   ├── Replay quotes during attestation
│   └── Bypass nonce checks
├── Reset TPM State
│   ├── Hardware TPM Reset
│   │   └── Power cycle/sleep without proper shutdown
│   ├── Software TPM Reset (for swtpm)
│   │   ├── Replace TPM state files
│   │   └── Restart TPM with old state
│   └── VM/Container Reset
│       ├── Rollback VM snapshot with old TPM state
│       └── Replace container TPM volume
└── Break TPM Security
    ├── Extract private keys from TPM
    ├── Forge signed quotes
    └── Exploit cryptographic weaknesses
```
```

### The Attacker
Depending on the deployment scenario, the attacker could be either:

#### Scenario 1: VM-based Deployment
- **Who**: Hypervisor admin (host) attacking guest VM 
- **Position**: Attacker is on the host, targeting Keylime running in a VM
- **Goal**: Make infected VM appear clean to external verifiers
- **Required Access**: Hypervisor/host admin privileges
- **Attack Method**: VM snapshot rollback or vTPM state manipulation

#### Scenario 2: Container-based Deployment
- **Who**: Container host admin attacking container integrity
- **Position**: Attacker is on the container host
- **Goal**: Make compromised container report clean measurements
- **Required Access**: Root on host running containers
- **Attack Method**: Manipulate TPM state files used by container

#### Scenario 3: Bare-metal Deployment
- **Who**: Root user with local access
- **Position**: Attacker has privileged access on the same system
- **Goal**: Hide malware from Keylime attestation
- **Required Access**: Root privileges or physical access
- **Attack Method**: Hardware reset or TPM state manipulation

### Real-World Examples (with vulnerable configurations)

#### Example 1: Container Host Attacking Container (Host → Container)
```bash
# Scenario: Container host admin manipulating TPM state of container
# Vulnerability: Unprotected TPM state files in Docker
# Attacker position: On the host running the Keylime agent container

# 1. Create backup when system is clean
docker cp keylime-agent:/tmp/tpmdir/tpm2-00.permall ./clean-permall
docker cp keylime-agent:/tmp/tpmdir/tpm2-00.volatilestate ./clean-volatile

# 2. Install malware inside the container
docker exec -it keylime-agent bash -c "echo 'malware' > /bin/evil"
docker exec -it keylime-agent chmod +x /bin/evil

# 3. Restore clean TPM state before attestation
docker stop keylime-agent
docker cp ./clean-permall keylime-agent:/tmp/tpmdir/tpm2-00.permall
docker cp ./clean-volatile keylime-agent:/tmp/tpmdir/tpm2-00.volatilestate
docker start keylime-agent

# Result: TPM will report pre-malware PCR values during attestation
# TPM Quote will contain old "clean" measurements despite malware presence
```

#### Example 2: Hypervisor Attacking VM (Host → VM)
```bash
# Scenario: Cloud admin manipulating guest VM state
# Vulnerability: VM snapshot rollback with vTPM
# Attacker position: On the hypervisor host with VM admin access

# 1. Create snapshot of clean VM state
virsh snapshot-create-as keylime-vm clean-state --disk-only

# 2. VM becomes compromised (either by admin or external attacker)
# (malware installs inside the VM)

# 3. Admin rolls back VM to clean snapshot before attestation
virsh snapshot-revert keylime-vm clean-state

# 4. Admin starts VM, allowing attestation to proceed
virsh start keylime-vm

# Result: VM's vTPM will report clean PCR values from snapshot
# despite the VM having been compromised previously
```

### Is Keylime Vulnerable?

✅ **PROTECTED AGAINST REPLAY ATTACKS**
- Random nonces prevent reusing old quotes
- TPM signature binds nonce to quote
- TPM counters detect resets

⚠️ **PARTIAL RISK FROM STATE RESET**
- **Host → VM attacks**: Hypervisor admins can roll back VM snapshots including vTPM state
- **Host → Container attacks**: Host root users can manipulate `/tmp/tpmdir` files used by containers
- **Nested virtualization gap**: TPM has no way to detect state rollbacks across virtualization boundaries

### Key Protections by Deployment Model

#### For VM-based Deployments (against Host → VM attacks)
1. **Trusted Compute Pools**: Use attestation for the hypervisor itself
2. **External TPM**: Use physical TPM passed through to VM (not vTPM)
3. **TPM Reset Monitoring**: Monitor TPM counter discontinuities across VM lifecycle:
   ```python
   # Example verifier code to track VM TPM reset counters
   prev_reset_count = agent_data.get('last_reset_count')
   current_reset_count = quote_data['tpm_quote']['clock_info']['reset_count']
   
   if prev_reset_count and current_reset_count < prev_reset_count:
       alert("Possible VM snapshot rollback detected!")
   
   agent_data['last_reset_count'] = current_reset_count
   ```

#### For Container-based Deployments (against Host → Container attacks)
1. **Hardware TPM**: Use physical TPM instead of software TPM
2. **Secure TPM State**: When using software TPM, protect state files:
   ```yaml
   # Docker compose example with secured TPM state
   keylime-agent:
     volumes:
       - type: tmpfs  # In-memory filesystem
         target: /tmp/tpmdir
         tmpfs:
           size: 100m
           mode: 0700  # Restrictive permissions
     read_only: true  # Read-only container filesystem
   ```
3. **Confidential Containers**: Use emerging technologies like AMD SEV or Intel TDX

#### For Bare-metal Deployments (against Root → Bare-metal attacks)
1. **Physical Security**: Restrict physical access to servers 
2. **TPM Firmware Updates**: Keep TPM firmware updated
3. **Boot Guard**: Use Intel Boot Guard or AMD Secure Boot
4. **Monitor TPM Events**: Log TPM_Startup events for unexpected resets

---

## Attack 2: TPM Resource Exhaustion

### How TPM Resources Work
1. TPM has limited resources:
   - Sessions (64 max in hardware TPM)
   - Handles for keys/objects
   - Memory for operations
2. Resource manager (tpm2-abrmd) controls access
3. Keylime agent uses TPM for each attestation

### Attack Goal
Prevent attestation by exhausting TPM resources (denial of service)

### Simplified Attack Tree
```
Goal: Prevent Attestation via Resource Exhaustion
├── Exhaust TPM Sessions
│   ├── Create many sessions without closing
│   ├── Keep sessions active to prevent timeouts
│   └── Bypass resource manager
├── Fill TPM Handle Space
│   ├── Create maximum persistent keys
│   ├── Fill transient object slots
│   └── Consume available TPM memory
├── Overload Agent Process
│   ├── Flood with concurrent quote requests
│   └── Send oversized parameters
└── Attack Resource Manager
    ├── Crash tpm2-abrmd
    └── Force excessive connections
```

### The Attacker
Unlike the TPM Reset/Replay attack, the resource exhaustion attack can be performed from multiple positions:

#### Scenario 1: Network-based Attacker → Agent (External)
- **Who**: Any network entity with access to the Keylime agent API
- **Position**: External network attacker targeting the agent's HTTP interface
- **Goal**: Prevent legitimate attestation by overwhelming agent resources
- **Required Access**: Network connectivity to agent port 9002
- **Attack Method**: HTTP request flooding against the `/quotes` endpoint

#### Scenario 2: VM Guest → TPM (Same Trust Domain)
- **Who**: Unprivileged user or process inside the VM running Keylime
- **Position**: Inside the same VM as the Keylime agent
- **Goal**: Prevent attestation by consuming TPM resources
- **Required Access**: Normal user access inside the VM
- **Attack Method**: Create many TPM sessions without proper cleanup

#### Scenario 3: VM/Container → Shared TPM (Resource Competition)
- **Who**: Other VMs or containers sharing the same physical or software TPM
- **Position**: Parallel workload competing for TPM resources
- **Goal**: Starve the target VM/container of TPM resources
- **Required Access**: Access to the shared TPM resource
- **Attack Method**: Legitimate but excessive TPM operations

### Real-World Examples (by attacker position)

#### Example 1: External Network → Agent (HTTP Flooding)
```bash
# Scenario: External attacker with network access
# Vulnerability: No rate limiting on agent API
# Attacker position: Any network position with access to agent

# HTTP request flooding against unprotected /quotes endpoint
for i in {1..1000}; do
  curl -k "https://agent:9002/quotes?nonce=$(openssl rand -hex 32)&pcrmask=0xFFFFFFFF" &
done
# Impact: Agent CPU/memory overwhelmed, legitimate verifier requests fail
```

#### Example 2: Inside VM → Local TPM (Session Exhaustion)
```bash
# Scenario: Unprivileged user inside the VM
# Vulnerability: TPM session handle exhaustion
# Attacker position: Inside the same VM as Keylime agent

# Create maximum TPM sessions without cleanup
for i in {1..100}; do
  # Each session consumes a TPM handle resource
  tpm2_startauthsession --tcti="device:/dev/tpm0" --session session_$i.ctx &
done
# Impact: TPM runs out of session handles, attestation operations fail
```

#### Example 3: Neighbor VM → Shared TPM (Resource Competition)
```bash
# Scenario: Multiple VMs sharing a vTPM
# Vulnerability: Shared TPM resources without isolation
# Attacker position: Another VM using the same hypervisor

# In the attacker VM: Create and use many persistent TPM keys
for i in {1..50}; do
  tpm2_create -C owner -G rsa2048 -u key_$i.pub -r key_$i.priv
  tpm2_load -C owner -u key_$i.pub -r key_$i.priv -c key_$i.ctx
  tpm2_evictcontrol -C o -c key_$i.ctx 0x81000000+$i
done

# Impact: Victim VM can't create its own TPM keys for attestation
```

### Is Keylime Vulnerable?

⚠️ **PARTIALLY VULNERABLE**
- **Missing rate limiting**: The agent's HTTP API (/quotes endpoint) has no request rate limits, allowing flooding attacks
- **Session tracking gap**: No tracking of active TPM sessions per client, allowing resource monopolization
- **Direct device access**: Local users can bypass tpm2-abrmd by accessing /dev/tpm0 directly if permissions allow
- **Error handling issue**: Some error paths in quote generation may not properly clean up TPM sessions

### Key Protections by Attack Vector

#### For External Network → Agent Attacks
1. Add API rate limiting to agent:
   ```rust
   // Example fix for keylime-agent/src/main.rs
   use actix_web::middleware::DefaultHeaders;
   use actix_ratelimit::{RateLimiter, MemoryStore};
   
   // In main HTTP server setup
   App::new()
       .wrap(RateLimiter::new(
           MemoryStore::new(),  // In-memory rate limit storage
           |req| format!("{}", req.peer_addr().unwrap()),  // Client IP key
           std::time::Duration::from_secs(60),  // 1-minute window
           5,  // Maximum 5 requests per minute
       ))
   ```

2. Set container resource limits:
   ```yaml
   # Docker compose resource limits
   keylime-agent:
     deploy:
       resources:
         limits:
           cpus: '0.5'
           memory: 256M
   ```

3. Implement verifier authentication:
   ```rust
   // Example API key authentication for verifier
   App::new()
       .service(
           web::resource("/quotes")
               .wrap(ApiKeyMiddleware::new("VERIFIER_API_KEY"))
               .route(web::get().to(get_quote))
       )
   ```

#### For VM Guest → Local TPM Attacks
1. Restrict TPM device access:
   ```bash
   # Restrict direct /dev/tpm0 access
   sudo chmod 600 /dev/tpm0
   sudo chown keylime-agent:keylime-agent /dev/tpm0
   ```

2. Monitor TPM resource usage:
   ```bash
   # Example monitoring script
   while true; do
     sessions=$(tpm2_getcap handles-loaded-session | wc -l)
     if [ "$sessions" -gt 40 ]; then
       logger -p auth.warning "TPM session count high: $sessions"
     fi
     sleep 30
   done
   ```

3. Configure proper TPM session timeouts:
   ```bash
   # Configure resource manager timeouts
   sudo mkdir -p /etc/tpm2-abrmd
   echo "session-timeout=30" | sudo tee /etc/tpm2-abrmd/config
   ```

#### For VM/Container → Shared TPM Attacks
1. TPM resource isolation:
   ```bash
   # Configure resource limits in tpm2-abrmd
   echo "max-sessions-per-connection=10" | sudo tee -a /etc/tpm2-abrmd/config
   echo "max-transient-objects=20" | sudo tee -a /etc/tpm2-abrmd/config
   ```

2. Use separate TPMs for critical workloads:
   ```yaml
   # Docker compose with dedicated software TPM
   keylime-agent:
     volumes:
       - type: volume
         source: keylime-agent-tpm-state
         target: /tmp/tpmdir
         volume:
           nocopy: true
   volumes:
     keylime-agent-tpm-state:
       driver: local
   ```

---

## Summary

### Attack 1: TPM Reset/Replay
- **Risk Level**: Low (outside trust boundary) to Medium (inside trust boundary)
- **Protection**: Strong against external attackers, weaker against hosting infrastructure
- **Specific Vulnerabilities by Trust Boundary**:
  1. **Host → VM attacks**: 
     - Hypervisor admins can roll back VM snapshots including vTPM state
     - VM's TPM has no way to detect this rollback from within the VM
     
  2. **Host → Container attacks**:
     - Software TPM state files in `/tmp/tpmdir` can be manipulated by host
     - Docker volumes storing TPM state can be backed up and restored
     
  3. **Root → Bare-metal attacks**:
     - ACPI sleep states (S3/S4) may not properly persist TPM state
     - Physical access can trigger hardware-level TPM resets
     
- **Fix**: Use hardware TPM, monitor resets, secure state files, trusted hosting

### Attack 2: TPM Resource Exhaustion
- **Risk Level**: Medium
- **Protection**: Moderate - Resource manager helps but not complete
- **Specific Vulnerabilities by Attacker Position**:

  1. **External Network → Agent**:
     - No rate limiting on `/quotes` endpoint in `keylime-agent/src/main.rs`
     - Agent lacks connection limits for concurrent requests
     - No client authentication for quote requests
     
  2. **VM Guest → Local TPM**:
     - Unprivileged users can access `/dev/tpm0` if permissions allow
     - No per-user TPM resource quotas
     - Some error paths might not properly release TPM resources
     
  3. **Neighbor VM/Container → Shared TPM**:
     - Insufficient isolation in multi-tenant environments
     - No resource quotas per VM/container
     - tpm2-abrmd configuration defaults may be too generous
     
- **Fix**: Add rate limiting, implement resource isolation, set container limits

### Bottom Line
Keylime has good protection against these attacks through its core design (nonces, signatures), but has specific implementation gaps:

1. **State Reset Vulnerabilities**:
   - **Host → VM attacks**: Hypervisor can roll back VM snapshots with vTPM state
   - **Host → Container attacks**: Container host can manipulate software TPM state files
   - **Root → Bare-metal attacks**: Physical access can trigger improper TPM resets

2. **Resource Exhaustion Vulnerabilities** (by attack vector):
   - **External → Agent**: Missing rate limiting in HTTP API (`keylime-agent/src/main.rs`)
   - **VM Guest → TPM**: Direct device access bypassing resource manager
   - **VM/Container → Shared TPM**: Incomplete resource isolation between tenants
   - **All scenarios**: Potential TPM resource leaks in error handling paths

These vulnerabilities are mostly implementation issues rather than design flaws and can be addressed with the suggested mitigations.
