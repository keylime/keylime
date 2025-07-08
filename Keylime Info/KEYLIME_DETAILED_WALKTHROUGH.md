# Keylime End-to-End Process Walkthrough

## Overview
This document provides a detailed, step-by-step explanation of how Keylime works from system startup to operational attestation, including what messages are passed, what data is verified, and potential attack surfaces.

## Phase 1: System Bootstrap and Initial Setup

### Step 1: System Boot and TPM Initialization
**What Happens:**
- UEFI firmware starts and measures itself into TPM PCR 0
- Secure Boot validates bootloader signature, measurements go to PCR 1-7
- GRUB bootloader measures kernel and initramfs into PCR 8-9
- Linux kernel initializes IMA subsystem
- IMA begins measuring file executions into PCR 10

**Messages/Data:**
```
PCR 0: UEFI firmware measurements
PCR 1-7: UEFI SecureBoot measurements  
PCR 8-9: Bootloader measurements (kernel, initramfs)
PCR 10: IMA runtime measurements (initially boot_aggregate)
```

**Verification:**
- Each component cryptographically verifies the next in chain
- Measurements create tamper-evident boot log
- TPM hardware ensures measurement integrity

**Attack Surface:**
- Firmware-level attacks (malicious UEFI)
- Bootloader tampering (if SecureBoot disabled)
- Early kernel exploits before IMA activation

### Step 2: Keylime Agent Startup
**What Happens:**
- Agent process starts after kernel initialization
- Communicates with TPM to establish cryptographic identity
- Reads configuration from `/etc/keylime/agent.conf`
- Initializes secure mount points for payload storage

**TPM Operations:**
```rust
// Rust agent initialization code
1. Read/Generate Endorsement Key (EK) - TPM identity
2. Generate Attestation Key (AK) - for quote signing  
3. Optionally generate DevID keys - device identity
4. Export public portions of all keys
```

**Data Structures:**
- EK: Hardware-backed TPM identity key (RSA 2048)
- AK: Software-generated attestation key (RSA 2048)
- EK Certificate: TPM manufacturer certificate for EK
- Agent UUID: Unique identifier for this agent instance

**Attack Surface:**
- Agent configuration tampering
- TPM communication interception
- Key extraction attempts

## Phase 2: Agent Registration with Registrar

### Step 3: Initial Registration Request
**What Happens:**
- Agent sends registration request to Registrar
- Includes public keys and certificates
- Registrar validates TPM identity

**HTTP Request:**
```http
POST /v1.2/agents/{agent_uuid}
Content-Type: application/json

{
    "ek_tpm": "<base64_EK_public_key>",
    "aik_tpm": "<base64_AK_public_key>",  
    "ekcert": "<EK_certificate_PEM>",
    "mtls_cert": "<agent_mTLS_cert>",
    "ip": "192.168.1.100",
    "port": 9002
}
```

**Registrar Validation Process:**
1. **EK Certificate Validation**: Verify EK cert chain to TPM manufacturer CA
2. **EK Key Binding**: Ensure EK public key matches certificate
3. **AK Validation**: Basic cryptographic validation of AK public key
4. **Database Storage**: Store agent identity information

**Attack Surface:**
- Registration flooding attacks
- Certificate validation bypasses
- Database injection via malformed data

### Step 4: TPM Credential Activation Challenge
**What Happens:**
- Registrar generates cryptographic challenge to verify AK-EK binding
- Uses TPM2_MakeCredential to encrypt challenge with EK
- Only the TPM with matching EK private key can decrypt

**Challenge Generation:**
```python
# Registrar generates challenge
challenge_nonce = os.urandom(32)
encrypted_blob = tpm2_makecredential(
    ek_public_key=agent.ek_tpm,
    ak_public_key=agent.aik_tpm, 
    challenge=challenge_nonce
)
```

**HTTP Response:**
```http
HTTP/1.1 200 OK
Content-Type: application/json

{
    "blob": "<base64_encrypted_challenge>",
    "code": 200,
    "status": "OK"
}
```

**Security Properties:**
- Only TPM with correct EK private key can decrypt
- Proves AK is bound to same TPM as EK
- Challenge includes both keys' information

**Attack Surface:**
- Challenge replay attacks
- TPM emulation attempts
- Cryptographic implementation flaws

### Step 5: Agent Challenge Response
**What Happens:**
- Agent receives encrypted challenge blob
- Uses TPM2_ActivateCredential to decrypt with EK private key
- Computes HMAC proof of challenge knowledge

**TPM Operations:**
```rust
// Agent processes challenge
let decrypted_key = tpm_context.activate_credential(
    challenge_blob,
    ak_handle,  // Attestation Key handle
    ek_handle   // Endorsement Key handle  
)?;

// Generate authentication tag
let auth_tag = crypto::compute_hmac(
    decrypted_key.as_bytes(),
    agent_uuid.as_bytes()
)?;
```

**HTTP Request:**
```http
PUT /v1.2/agents/{agent_uuid}
Content-Type: application/json

{
    "auth_tag": "<hex_encoded_hmac>"
}
```

**Verification:**
- Registrar recomputes expected HMAC
- Compares with agent's response
- Marks agent as "active" if match

**Attack Surface:**
- HMAC timing attacks
- Challenge response replay
- TPM key extraction

## Phase 3: Agent Enrollment with Verifier

### Step 6: Tenant Adds Agent to Verifier
**What Happens:**
- Administrator uses tenant CLI to add agent for monitoring
- Specifies policies and optionally secure payload
- Verifier begins continuous attestation

**Tenant Command:**
```bash
keylime_tenant -c add \
    --uuid d432fbb3-d2f1-4a97-9ef7-75bd81c00000 \
    --runtime-policy runtime_policy.json \
    --tpm-policy '{"mask": "0x408000"}' \
    -f secure_payload.zip
```

**Policy Structures:**
```json
{
    "tpm_policy": {
        "mask": "0x408000",  // Monitor PCRs 15, 22
        "pcrs": {
            "15": ["expected_hash_1", "expected_hash_2"],
            "22": "expected_hash"
        }
    },
    "runtime_policy": {
        "digests": {
            "/bin/bash": ["sha256:abc123..."],
            "/usr/lib/systemd": ["sha256:def456..."]
        },
        "excludes": ["/tmp/*", "/var/log/*"]
    }
}
```

**Attack Surface:**
- Policy injection attacks
- Malicious payload delivery
- Weak policy configurations

## Phase 4: Continuous Attestation Cycle

### Step 7: Quote Request and Generation
**What Happens (every ~30 seconds):**
- Verifier requests fresh attestation from agent
- Agent generates TPM quote with current PCR values
- Includes IMA measurement log and event logs

**HTTP Request:**
```http
GET /quotes?nonce=abc123&pcrmask=0x408000&compress=zlib
Host: agent:9002
```

**TPM Quote Generation:**
```rust
// Agent generates quote
let quote_result = tpm_context.quote(
    ak_handle,           // Attestation key for signing
    nonce.as_bytes(),    // Freshness nonce from verifier
    signature_scheme,    // RSA-PSS typically
    pcr_selection       // Which PCRs to include
)?;

let (attestation, signature, pcr_values) = quote_result;
```

**Quote Structure:**
```
TPM Quote = {
    magic: 0xFF544347,
    type: TPM_ST_ATTEST_QUOTE,
    clock_info: {time, reset_count, restart_count, safe},
    firmware_version: 0x...,
    attested: {
        pcr_select: {hash_alg, pcr_bitmap},
        pcr_digest: SHA256(concatenated_pcr_values)
    }
}
Signature = RSA_PSS_Sign(AK_private, Quote)
```

**Attack Surface:**
- Quote replay attacks
- Nonce prediction
- PCR reset attacks
- Time-of-check vs time-of-use races

### Step 8: IMA Measurement Collection
**What Happens:**
- Agent reads current IMA measurement log
- Includes all file executions since boot
- Provides runtime integrity evidence

**IMA Log Format:**
```
PCR     Template    Hash                                            Path
10 ima-ng sha256:a1b2c3... /bin/systemd
10 ima-ng sha256:d4e5f6... /lib/x86_64-linux-gnu/libc.so.6
10 ima-ng sha256:g7h8i9... /usr/bin/bash
10 ima-sig sha256:j1k2l3... /usr/sbin/sshd
```

**Measurement Types:**
- **ima-ng**: File hash measurements
- **ima-sig**: File hash + digital signature
- **ima-buf**: Buffer measurements (keys, firmware)

**Attack Surface:**
- IMA bypass techniques
- Measurement log tampering
- TOCTOU attacks on file measurements

### Step 9: Quote Validation and Policy Checking
**What Happens:**
- Verifier receives quote + measurements
- Validates cryptographic integrity
- Checks against configured policies

**Validation Steps:**
```python
# 1. Verify quote signature
public_key = get_ak_public_key(agent_id)
if not verify_signature(quote, signature, public_key):
    fail_agent("Invalid quote signature")

# 2. Verify nonce freshness  
if quote.nonce != expected_nonce:
    fail_agent("Stale quote")

# 3. Check PCR values against policy
for pcr_num, pcr_value in quote.pcr_values:
    if pcr_value not in tpm_policy[pcr_num]:
        fail_agent(f"PCR {pcr_num} mismatch")

# 4. Process IMA measurements
for measurement in ima_log:
    if not validate_ima_measurement(measurement, runtime_policy):
        fail_agent("IMA policy violation")
```

**Policy Enforcement Logic:**
```python
# TPM Policy Check
def check_tpm_policy(pcr_dict, policy):
    for pcr_num, expected_values in policy["pcrs"].items():
        actual_value = pcr_dict.get(int(pcr_num))
        if actual_value not in expected_values:
            return False, f"PCR {pcr_num}: got {actual_value}, expected {expected_values}"
    return True, "OK"

# IMA Runtime Policy Check  
def check_ima_policy(ima_measurements, runtime_policy):
    for measurement in ima_measurements:
        file_path = measurement.file_path
        file_hash = measurement.file_hash
        
        # Check if file is in exclude list
        if any(fnmatch(file_path, pattern) for pattern in runtime_policy["excludes"]):
            continue
            
        # Check if hash is in allowlist
        if file_path in runtime_policy["digests"]:
            if file_hash not in runtime_policy["digests"][file_path]:
                return False, f"File {file_path}: unexpected hash {file_hash}"
        else:
            return False, f"File {file_path}: not in allowlist"
    
    return True, "OK"
```

**Attack Surface:**
- Policy bypass techniques
- Time-based policy evasion
- Hash collision attacks
- Signature forgery

## Phase 5: Secure Payload Provisioning

### Step 10: Key Split and Payload Encryption
**What Happens:**
- Tenant encrypts payload with symmetric key K
- Splits K into U_key (user) and V_key (verifier)  
- Agent gets U_key + encrypted payload immediately
- Verifier holds V_key until attestation succeeds

**Cryptographic Protocol:**
```python
# Tenant splits encryption key
import os
from cryptography.fernet import Fernet

# Generate random 256-bit key
master_key = os.urandom(32)

# Split into two parts using XOR
u_key = os.urandom(32)  # User key (sent to agent)
v_key = bytes(a ^ b for a, b in zip(master_key, u_key))  # Verifier key

# Encrypt payload
encrypted_payload = Fernet(master_key).encrypt(payload_data)
```

**Initial Distribution:**
```
Agent receives: {u_key, encrypted_payload}
Verifier stores: {v_key, agent_uuid}
```

**Security Properties:**
- Neither U_key nor V_key alone can decrypt payload
- Agent cannot access payload until verification succeeds
- Verifier controls payload access through attestation

**Attack Surface:**
- Key reconstruction timing attacks
- Memory dumping for key extraction
- Side-channel analysis during decryption

### Step 11: Attestation-Based Key Release
**What Happens:**
- When agent passes attestation, verifier sends V_key
- Agent reconstructs master key and decrypts payload
- Extracted to secure tmpfs mount for protection

**V_key Delivery:**
```http
POST /keys/{agent_uuid}
Content-Type: application/json

{
    "v": "<base64_v_key>",
    "uuid": "agent_uuid"  
}
```

**Agent Payload Processing:**
```rust
// Reconstruct encryption key
let master_key: Vec<u8> = u_key.iter()
    .zip(v_key.iter())
    .map(|(a, b)| a ^ b)
    .collect();

// Decrypt payload
let decrypted_data = decrypt_aes_gcm(encrypted_payload, &master_key)?;

// Extract to secure mount (tmpfs)
extract_to_secure_mount(&decrypted_data, "/var/lib/keylime/secure")?;

// Execute autorun script if present
if let Ok(script) = fs::read_to_string("/var/lib/keylime/secure/autorun.sh") {
    execute_secure_script(script)?;
}
```

**Security Properties:**
- Payload stored in memory-only filesystem (tmpfs)
- Automatic cleanup on system reboot
- Execution in controlled environment

**Attack Surface:**
- Memory dumping attacks on tmpfs
- Script injection in autorun
- Race conditions during extraction

## Phase 6: Policy Violation and Revocation

### Step 12: Attestation Failure Detection
**What Happens:**
- Verifier detects policy violation (bad PCR, IMA failure)
- Marks agent as "Invalid Quote" or "Failed"
- Stops sending V_key for new payloads
- Initiates revocation notification process

**Failure Scenarios:**
```python
# Common failure modes
FAILURE_TYPES = {
    "invalid_quote": "Quote signature verification failed",
    "pcr_mismatch": "PCR values don't match policy", 
    "ima_violation": "IMA measurement not in allowlist",
    "stale_quote": "Quote nonce is not fresh",
    "timing_violation": "Attestation response too slow"
}
```

**Verifier Actions:**
```python
def handle_attestation_failure(agent_id, failure_type, details):
    # 1. Update agent status
    agent.operational_state = "Failed"
    agent.last_failure = failure_type
    
    # 2. Stop providing V_keys
    revoke_payload_access(agent_id)
    
    # 3. Generate revocation notification
    revocation_msg = create_revocation_notification(agent_id, failure_type, details)
    
    # 4. Sign and distribute revocation
    signed_revocation = sign_revocation(revocation_msg, revocation_key)
    distribute_revocation(signed_revocation)
```

**Attack Surface:**
- False positive policy violations
- Revocation message tampering
- Denial of service via induced failures

### Step 13: Revocation Notification and Response
**What Happens:**
- Verifier creates signed revocation notification
- Distributes to all agents in system
- Affected agents execute revocation actions
- System-wide policy enforcement

**Revocation Message:**
```json
{
    "type": "revocation",
    "agent_uuid": "d432fbb3-d2f1-4a97-9ef7-75bd81c00000",
    "failure_type": "ima_violation", 
    "timestamp": "2025-07-08T10:30:00Z",
    "details": {
        "violated_file": "/bin/malicious_binary",
        "expected_hash": "sha256:abc123...",
        "actual_hash": "sha256:def456..."
    }
}
```

**Digital Signature:**
```
signature = RSA_PSS_Sign(revocation_private_key, revocation_message)
```

**Agent Revocation Actions:**
```python
# Example revocation action script
def execute_revocation_action(revocation_data):
    failed_agent = revocation_data["agent_uuid"]
    
    # Remove from SSH authorized_keys
    remove_ssh_access(failed_agent)
    
    # Revoke certificates
    revoke_certificate(failed_agent)
    
    # Update firewall rules  
    block_network_access(failed_agent)
    
    # Log security event
    log_security_incident(revocation_data)
```

**Attack Surface:**
- Revocation message forgery
- Selective revocation blocking
- Revocation action bypassing
- Certificate revocation delays

## Data Flow Summary

### Startup Data Flow:
```
UEFI/BIOS → TPM PCRs 0-7 → Bootloader → TPM PCRs 8-9 → 
Kernel → IMA → TPM PCR 10 → Agent → TPM AK/EK → Registrar
```

### Registration Data Flow:
```
Agent (EK_pub, AK_pub, certs) → Registrar → 
Registrar (encrypted_challenge) → Agent → 
Agent (HMAC_response) → Registrar (validation)
```

### Attestation Data Flow:
```
Verifier (nonce, pcr_mask) → Agent → 
TPM (quote + signature) → Agent → 
Agent (quote + IMA_log + event_log) → Verifier (validation)
```

### Payload Data Flow:
```
Tenant (K = U_key ⊕ V_key, encrypted_payload) → 
Agent (U_key, encrypted_payload) + Verifier (V_key) →
[Attestation Success] → Verifier (V_key) → Agent → 
Agent (reconstructed K, decrypted_payload)
```

### Revocation Data Flow:
```
Verifier (failure_detection) → 
Verifier (signed_revocation_message) → All_Agents → 
Agents (revocation_actions)
```

## Key Verification Points

### Cryptographic Verification:
1. **TPM Quote Signatures**: RSA-PSS signature with AK private key
2. **EK Certificate Chain**: X.509 validation to TPM manufacturer CA  
3. **Revocation Signatures**: RSA signature with verifier revocation key
4. **TLS/mTLS**: All network communication encrypted and authenticated

### Integrity Verification:
1. **PCR Values**: Hardware-attested measurements of boot process
2. **IMA Measurements**: Kernel-level file integrity measurements  
3. **Policy Compliance**: Runtime behavior matches expected policy
4. **Freshness**: Nonce-based replay attack prevention

### Identity Verification:
1. **TPM Binding**: AK cryptographically bound to EK
2. **Registration Challenge**: Proof of TPM possession
3. **Certificate Validation**: X.509 certificate chain verification
4. **UUID Consistency**: Agent identity maintained across interactions
