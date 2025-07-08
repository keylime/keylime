# Keylime Visual Architecture Summary

## Quick Reference Guide

This document provides a high-level visual summary of Keylime's architecture and workflows, complementing the detailed documentation in the other files.

## Core Architecture Overview

```mermaid
graph TB
    subgraph "Measured Boot Chain"
        UEFI[UEFI Firmware<br/>PCR 0-7]
        GRUB[GRUB Bootloader<br/>PCR 8-9]
        KERNEL[Linux Kernel<br/>PCR 10+]
        IMA[IMA/EVM Runtime<br/>PCR 10 logs]
    end
    
    subgraph "Keylime Agent Node"
        TPM[TPM 2.0<br/>Hardware Root of Trust]
        AGENT[Keylime Agent<br/>Rust Service]
        SECURE[Secure Mount<br/>Payload Storage]
    end
    
    subgraph "Keylime Infrastructure"
        REG[Registrar<br/>Agent Registry]
        VER[Verifier<br/>Attestation Engine]
        CA[Certificate Authority<br/>Trust Anchor]
    end
    
    subgraph "Management Interface"
        TENANT[Tenant CLI<br/>Policy Management]
        POLICY[Runtime Policies<br/>Allow/Deny Lists]
    end
    
    %% Boot Chain
    UEFI --> GRUB
    GRUB --> KERNEL
    KERNEL --> IMA
    
    %% Agent Relationships
    TPM <--> AGENT
    IMA <--> AGENT
    AGENT <--> SECURE
    
    %% Network Communications
    AGENT <--> REG
    AGENT <--> VER
    TENANT <--> VER
    TENANT <--> REG
    VER <--> POLICY
    
    %% Trust Relationships
    TPM -.-> CA
    REG -.-> CA
    VER -.-> CA
```

## Key Security Properties

### 1. Hardware Root of Trust
- **TPM 2.0**: Provides cryptographic identity and secure measurement storage
- **Measured Boot**: Creates tamper-evident boot log in PCR registers
- **Remote Attestation**: Enables cryptographic proof of system state

### 2. Cryptographic Attestation Flow
```mermaid
sequenceDiagram
    participant A as Agent
    participant T as TPM
    participant R as Registrar
    participant V as Verifier
    
    Note over A,V: Initial Registration
    A->>R: Send EK/AK Public Keys
    R->>A: Credential Activation Challenge
    A->>T: Decrypt Challenge with EK
    T->>A: Return Decrypted Credential
    A->>R: Prove Key Binding
    
    Note over A,V: Ongoing Attestation
    V->>A: Request Quote + Nonce
    A->>T: Generate Quote (PCRs + Nonce)
    T->>A: Signed Quote with AK
    A->>V: Return Quote + IMA Log
    V->>V: Verify Quote & Policy
```

### 3. Threat Model Coverage

| **Attack Vector** | **Protection Mechanism** | **Limitations** |
|-------------------|-------------------------|------------------|
| Boot-time Tampering | Measured Boot + PCR Verification | Depends on Secure Boot |
| Runtime File Modification | IMA Measurements + Policy | Policy Completeness |
| Network MITM | mTLS + Certificate Validation | Certificate Management |
| TPM Attacks | Hardware Security Module | Physical Access |
| Agent Compromise | Secure Mount + Revocation | Agent Process Security |

## Component Interaction Matrix

```mermaid
graph LR
    subgraph "Trust Establishment"
        T1[TPM Identity<br/>EK/AK Keys]
        T2[Certificate Chain<br/>CA Validation]
        T3[Credential Activation<br/>Challenge/Response]
    end
    
    subgraph "Runtime Operations"
        R1[Quote Generation<br/>PCR + Nonce]
        R2[Policy Evaluation<br/>Allow/Deny Lists]
        R3[Secure Provisioning<br/>Payload Delivery]
    end
    
    subgraph "Incident Response"
        I1[Revocation Events<br/>Policy Violations]
        I2[Payload Cleanup<br/>Secure Deletion]
        I3[Re-attestation<br/>Recovery Process]
    end
    
    T1 --> R1
    T2 --> R2
    T3 --> R3
    
    R1 --> I1
    R2 --> I2
    R3 --> I3
```

## Attack Surface Quick Reference

### High-Priority Targets
1. **Agent REST API** (Port 9002) - Quote manipulation, payload injection
2. **Registrar Database** - Agent identity spoofing, SQL injection
3. **Verifier Policy Engine** - Policy bypass, logic flaws
4. **TPM Communication** - Quote replay, measurement manipulation

### Common Vulnerability Patterns
- **Input Validation**: Malformed JSON, oversized payloads
- **Authentication**: JWT manipulation, certificate bypass
- **Cryptographic**: Timing attacks, weak randomness
- **Logic**: Race conditions, state confusion

## Research Directions Summary

### 1. Protocol-Level Attacks
- **Quote Replay**: Timestamp validation bypasses
- **Nonce Manipulation**: Freshness guarantee violations
- **Certificate Attacks**: CA compromise, weak validation

### 2. Implementation Vulnerabilities
- **Memory Safety**: Buffer overflows in quote processing
- **Race Conditions**: Concurrent access to shared state
- **Error Handling**: Information leakage through exceptions

### 3. Architectural Weaknesses
- **Trust Assumptions**: CA compromise scenarios
- **Scalability**: Resource exhaustion attacks
- **Recovery**: Revocation and re-attestation flaws

## Deployment Considerations

### Secure Configuration
```yaml
# Example secure configuration
keylime:
  agent:
    secure_size: "1G"
    tpm_ownerpassword: "generated_password"
    trusted_payload_path: "/opt/keylime/secure_payloads"
    
  verifier:
    quote_interval: 30
    policy_dir: "/etc/keylime/policies"
    revocation_notifier: "webhook"
    
  registrar:
    database_url: "sqlite:///var/lib/keylime/cv_data.sqlite"
    auto_migrate_db: true
```

### Monitoring Points
- **Agent Health**: Quote generation success/failure
- **Network Traffic**: TLS handshake anomalies
- **TPM Status**: PCR measurement discrepancies
- **Policy Violations**: Real-time alert triggers

## Integration with Existing Security

### SIEM Integration
```python
# Example log format for SIEM
{
    "timestamp": "2024-01-15T10:30:45Z",
    "component": "keylime_verifier",
    "event": "quote_validation_failed",
    "agent_id": "uuid-12345",
    "pcr_mismatch": ["10"],
    "policy_violation": "unauthorized_file_execution",
    "severity": "high"
}
```

### Compliance Frameworks
- **NIST SP 800-155**: Measured Boot requirements
- **Common Criteria**: TPM evaluation standards
- **FIPS 140-2**: Cryptographic module validation

---