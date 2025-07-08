# Keylime Complete Sequence Diagrams

## End-to-End System Flow

This document provides comprehensive sequence diagrams showing every step of Keylime's operation from boot to operational attestation.

## Phase 1: Docker Container Boot and Initialization

```mermaid
sequenceDiagram
    participant HOST as Host System
    participant DOCKER as Docker Engine
    participant REG as keylime-registrar
    participant VER as keylime-verifier
    participant AGENT as keylime-agent
    participant SWTPM as Software TPM
    participant ABRMD as TPM2-ABRMD
    participant DBUS as D-Bus
    
    Note over HOST,DOCKER: Docker Compose Startup
    
    HOST->>DOCKER: docker-compose up
    DOCKER->>REG: Start registrar container
    REG->>REG: Initialize Python service
    REG->>REG: Bind to :8890 (registration), :8891 (management)
    REG->>REG: Load keylime-data volume
    
    DOCKER->>VER: Start verifier container (depends_on: registrar)
    VER->>VER: Initialize Python service
    VER->>VER: Bind to :8880 (internal), :8881 (tenant)
    VER->>VER: Load keylime-data volume
    
    Note over DOCKER,AGENT: Agent Container Initialization
    
    DOCKER->>AGENT: Start agent container (privileged: true)
    AGENT->>AGENT: mkdir -p /tmp/tpmdir /var/lib/keylime
    AGENT->>AGENT: Create keylime user, tss group
    AGENT->>AGENT: chown -R keylime:tss /var/lib/keylime
    
    Note over AGENT,DBUS: System Services Setup
    
    AGENT->>DBUS: rm -rf /var/run/dbus && mkdir /var/run/dbus
    AGENT->>DBUS: dbus-daemon --system
    
    Note over AGENT,SWTPM: Software TPM Setup
    
    AGENT->>SWTPM: swtpm_setup --tpm2 --tpmstate /tmp/tpmdir
    SWTPM->>SWTPM: --createek --decryption --create-ek-cert
    SWTPM->>SWTPM: --create-platform-cert --display
    AGENT->>SWTPM: swtpm socket --tpm2 --tpmstate dir=/tmp/tpmdir
    SWTPM->>SWTPM: --flags startup-clear --daemon
    SWTPM->>SWTPM: Listen on TCP ports 2321 (data), 2322 (control)
    
    Note over AGENT,ABRMD: TPM Resource Manager
    
    AGENT->>ABRMD: tpm2-abrmd --logger=stdout --tcti=swtpm:
    ABRMD->>ABRMD: --allow-root --flush-all &
    ABRMD->>SWTPM: Connect to software TPM
    
    Note over AGENT,REG: Service Discovery
    
    AGENT->>REG: getent hosts registrar (DNS resolution)
    loop DNS Resolution Check
        AGENT->>REG: Check if registrar hostname resolves
        REG->>AGENT: DNS response or timeout
    end
    
    AGENT->>REG: nc -z registrar 8891 (port availability)
    REG->>AGENT: Port connection successful
    
    Note over AGENT,AGENT: Agent Process Start
    
    AGENT->>AGENT: touch /var/lib/keylime/agent_data.json
    AGENT->>AGENT: chown keylime:tss agent_data.json
    AGENT->>AGENT: chmod 660 agent_data.json
    AGENT->>AGENT: exec /usr/bin/keylime_agent
```

## Phase 2: Agent Registration Process

```mermaid
sequenceDiagram
    participant AGENT as Keylime Agent
    participant REG as Registrar
    participant TPM as TPM 2.0
    participant CA as Certificate Authority
    
    Note over AGENT,CA: Initial Registration
    
    AGENT->>REG: POST /v1.2/agents/{uuid}<br/>Send EK/AK public keys + EK cert
    
    REG->>CA: Validate EK certificate chain
    CA->>REG: Certificate validation result
    
    REG->>REG: Validate EK public key against cert
    REG->>REG: Store agent identity in database
    
    Note over AGENT,CA: Credential Activation Challenge
    
    REG->>REG: Generate random credential
    REG->>REG: TPM2_MakeCredential(EK_pub, AK_pub, credential)
    REG->>AGENT: Send encrypted credential blob
    
    AGENT->>TPM: TPM2_ActivateCredential(EK_handle, AK_handle, blob)
    TPM->>AGENT: Return decrypted credential
    
    AGENT->>REG: Send decrypted credential (proof of key binding)
    REG->>REG: Verify credential matches
    REG->>REG: Mark agent as registered
    REG->>AGENT: Registration success
```

## Phase 3: Verifier Setup and Agent Enrollment

```mermaid
sequenceDiagram
    participant TENANT as Tenant CLI
    participant VER as Verifier
    participant REG as Registrar
    participant AGENT as Keylime Agent
    participant TPM as TPM 2.0
    
    Note over TENANT,TPM: Agent Enrollment
    
    TENANT->>VER: POST /v2.0/agents/{uuid}<br/>Enroll agent with policies
    
    VER->>REG: GET /v1.2/agents/{uuid}<br/>Retrieve agent public keys
    REG->>VER: Return EK/AK public keys
    
    VER->>VER: Store agent info and policies
    VER->>VER: Generate initial nonce
    
    Note over TENANT,TPM: Initial Attestation
    
    VER->>AGENT: GET /v2.0/quotes/integrity<br/>Request quote with nonce
    
    AGENT->>TPM: TPM2_Quote(AK_handle, PCR_selection, nonce)
    TPM->>AGENT: Return signed quote
    
    AGENT->>IMA: Read IMA runtime log
    IMA->>AGENT: Return measurement list
    
    AGENT->>VER: Return quote + IMA log
    
    VER->>VER: Verify quote signature with AK
    VER->>VER: Validate PCR values
    VER->>VER: Process IMA log against policies
    
    alt Quote Valid
        VER->>VER: Mark agent as trusted
        VER->>TENANT: Enrollment successful
    else Quote Invalid
        VER->>VER: Mark agent as untrusted
        VER->>TENANT: Enrollment failed
    end
```

## Phase 4: Ongoing Attestation Cycle

```mermaid
sequenceDiagram
    participant VER as Verifier
    participant AGENT as Keylime Agent
    participant TPM as TPM 2.0
    participant IMA as IMA Subsystem
    participant POLICY as Policy Engine
    
    Note over VER,POLICY: Continuous Attestation Loop
    
    loop Every 30 seconds (configurable)
        VER->>VER: Generate fresh nonce
        VER->>AGENT: GET /v2.0/quotes/integrity<br/>Request quote + nonce
        
        AGENT->>TPM: TPM2_Quote(AK_handle, PCR_selection, nonce)
        TPM->>AGENT: Return signed quote
        
        AGENT->>IMA: Read IMA runtime log since last check
        IMA->>AGENT: Return incremental measurement list
        
        AGENT->>VER: Return quote + IMA log
        
        VER->>VER: Verify quote signature
        VER->>VER: Validate nonce freshness
        VER->>VER: Check PCR values
        
        VER->>POLICY: Evaluate IMA measurements
        POLICY->>POLICY: Check against allow/deny lists
        
        alt All Checks Pass
            POLICY->>VER: Policy compliance confirmed
            VER->>VER: Update agent trust status
        else Policy Violation
            POLICY->>VER: Policy violation detected
            VER->>VER: Trigger revocation process
        end
    end
```

## Phase 5: Secure Payload Provisioning

```mermaid
sequenceDiagram
    participant TENANT as Tenant CLI
    participant VER as Verifier
    participant AGENT as Keylime Agent
    participant TPM as TPM 2.0
    participant SECURE as Secure Mount
    
    Note over TENANT,SECURE: Payload Provisioning Flow
    
    TENANT->>VER: POST /v2.0/agents/{uuid}/payloads<br/>Upload encrypted payload
    
    VER->>VER: Verify agent is trusted
    VER->>VER: Generate payload key
    VER->>VER: Encrypt payload with key
    
    VER->>AGENT: POST /v2.0/keys/payload<br/>Deliver encrypted payload
    
    AGENT->>AGENT: Verify verifier signature
    AGENT->>TPM: Decrypt payload key with AK
    TPM->>AGENT: Return decrypted key
    
    AGENT->>SECURE: Store payload in secure mount
    SECURE->>AGENT: Confirm storage
    
    AGENT->>AGENT: Execute autorun script (if present)
    AGENT->>VER: Confirm payload receipt
    
    VER->>TENANT: Payload provisioning complete
```

## Phase 6: Policy Violation and Revocation

```mermaid
sequenceDiagram
    participant VER as Verifier
    participant AGENT as Keylime Agent
    participant POLICY as Policy Engine
    participant WEBHOOK as Webhook Notifier
    participant SECURE as Secure Mount
    
    Note over VER,SECURE: Revocation Flow
    
    VER->>AGENT: Request attestation quote
    AGENT->>VER: Return quote + IMA log
    
    VER->>POLICY: Evaluate measurements
    POLICY->>POLICY: Detect unauthorized file execution
    POLICY->>VER: VIOLATION: Malicious binary detected
    
    VER->>VER: Add agent to revocation list
    VER->>WEBHOOK: Send revocation notification
    
    VER->>AGENT: POST /v2.0/keys/revoke<br/>Revoke all keys
    
    AGENT->>SECURE: Wipe secure mount
    SECURE->>AGENT: Secure deletion complete
    
    AGENT->>AGENT: Disable payload execution
    AGENT->>VER: Confirm revocation
    
    VER->>VER: Mark agent as revoked
    
    Note over VER,SECURE: Recovery Process
    
    alt System Cleaned
        VER->>AGENT: Request new attestation
        AGENT->>VER: Return clean quote
        VER->>VER: Re-evaluate trust status
    else System Still Compromised
        VER->>VER: Maintain revocation status
        VER->>WEBHOOK: Send persistent violation alert
    end
```

## Phase 7: Error Handling and Recovery

```mermaid
sequenceDiagram
    participant VER as Verifier
    participant AGENT as Keylime Agent
    participant TPM as TPM 2.0
    participant REG as Registrar
    
    Note over VER,REG: Error Scenarios
    
    VER->>AGENT: Request attestation quote
    
    alt TPM Error
        AGENT->>TPM: TPM2_Quote request
        TPM->>AGENT: TPM_RC_FAILURE
        AGENT->>VER: HTTP 500 - TPM Error
        VER->>VER: Log TPM failure
        VER->>VER: Retry with backoff
    
    else Network Error
        VER->>AGENT: Request quote (timeout)
        VER->>VER: Connection timeout
        VER->>VER: Increment failure count
        
        alt Max Failures Reached
            VER->>VER: Mark agent as unreachable
            VER->>REG: Update agent status
        else Retry Available
            VER->>VER: Schedule retry
        end
    
    else Quote Validation Error
        AGENT->>VER: Return malformed quote
        VER->>VER: Quote signature verification fails
        VER->>VER: Log validation error
        VER->>VER: Request fresh quote
    end
```

## Security Event Timeline

```mermaid
timeline
    title Keylime Security Event Timeline
    
    section Boot Phase
        T+0s    : UEFI Measurements
                : PCR 0-7 Extended
        T+5s    : Bootloader Phase
                : PCR 8-9 Extended
        T+10s   : Kernel Boot
                : IMA Initialized
                : PCR 10 Extended
    
    section Registration Phase
        T+30s   : Agent Startup
                : TPM Initialization
                : EK/AK Generation
        T+35s   : Registrar Contact
                : Identity Validation
                : Credential Challenge
        T+40s   : Registration Complete
                : Agent Database Entry
    
    section Attestation Phase
        T+60s   : First Quote Request
                : Baseline Establishment
        T+90s   : Continuous Attestation
                : 30-second intervals
        T+120s  : Policy Evaluation
                : IMA Log Processing
    
    section Operational Phase
        T+180s  : Payload Provisioning
                : Secure Delivery
        T+240s  : Runtime Monitoring
                : Policy Enforcement
        T+300s  : Violation Detection
                : Revocation Trigger
```

## Message Format Reference

### Quote Request/Response
```json
{
  "request": {
    "nonce": "base64_encoded_random_bytes",
    "pcrmask": "0x408001",
    "ima_ml_entry": 0
  },
  "response": {
    "quote": "base64_encoded_tpm_quote",
    "ima_measurement_list": "base64_encoded_ima_log",
    "boottime": "2024-01-15T10:30:00Z"
  }
}
```

### Registration Data
```json
{
  "ek_tpm": "base64_encoded_ek_public_key",
  "aik_tpm": "base64_encoded_ak_public_key",
  "ekcert": "PEM_encoded_ek_certificate",
  "mtls_cert": "PEM_encoded_mtls_certificate",
  "ip": "192.168.1.100",
  "port": 9002
}
```

### Policy Violation Event
```json
{
  "agent_id": "uuid-12345",
  "timestamp": "2024-01-15T10:30:45Z",
  "violation_type": "ima_policy_violation",
  "details": {
    "file_path": "/bin/malicious_binary",
    "ima_signature": "invalid",
    "policy_action": "deny"
  },
  "severity": "high"
}
```

---