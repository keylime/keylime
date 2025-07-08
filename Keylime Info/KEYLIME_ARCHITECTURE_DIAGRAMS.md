# Keylime Architecture and Workflow Analysis

## Table of Contents
1. [Overall System Architecture](#overall-system-architecture)
2. [Component Interaction Diagrams](#component-interaction-diagrams)
3. [Startup and Registration Workflow](#startup-and-registration-workflow)
4. [Attestation Cycle](#attestation-cycle)
5. [Secure Payload Provisioning](#secure-payload-provisioning)
6. [Policy Enforcement and Revocation](#policy-enforcement-and-revocation)
7. [Attack Surface Analysis](#attack-surface-analysis)

## Overall System Architecture

```mermaid
graph TB
    subgraph "Trust Domain"
        TPM[TPM 2.0<br/>Hardware Security Module]
        IMA[IMA/EVM<br/>Kernel Subsystem]
        Agent[Keylime Agent<br/>(Rust)]
    end
    
    subgraph "Infrastructure"
        Registrar[Keylime Registrar<br/>(Python)]
        Verifier[Keylime Verifier<br/>(Python)]
        CA[Certificate Authority<br/>& Key Management]
    end
    
    subgraph "Management"
        Tenant[Keylime Tenant CLI<br/>(Python)]
        Policy[Runtime Policies<br/>& Configuration]
    end
    
    subgraph "Boot Chain"
        UEFI[UEFI Firmware]
        SecureBoot[Secure Boot]
        Bootloader[GRUB2 Bootloader]
        Kernel[Linux Kernel]
        InitRamFS[InitramFS]
    end
    
    %% Core Relationships
    Agent <--> TPM
    Agent <--> IMA
    Agent <--> Registrar
    Agent <--> Verifier
    Tenant <--> Verifier
    Tenant <--> Registrar
    Verifier <--> Policy
    
    %% Boot Chain Flow
    UEFI --> SecureBoot
    SecureBoot --> Bootloader
    Bootloader --> Kernel
    Kernel --> InitRamFS
    InitRamFS --> Agent
    
    %% Measurement Chain
    UEFI -.-> TPM
    SecureBoot -.-> TPM
    Bootloader -.-> TPM
    Kernel -.-> TPM
    InitRamFS -.-> TPM
    IMA -.-> TPM
    
    style TPM fill:#ff9999
    style IMA fill:#99ff99
    style Agent fill:#9999ff
    style Verifier fill:#ffff99
    style Registrar fill:#ff99ff
```

## Component Roles and Responsibilities

### TPM (Trusted Platform Module)
- **Primary Role**: Hardware Root of Trust
- **Key Functions**:
  - Stores cryptographic keys (EK, AK, DevID keys)
  - Generates attestation quotes
  - Maintains Platform Configuration Registers (PCRs)
  - Provides secure key storage and cryptographic operations
- **Security Properties**: Tamper-resistant, authenticated boot measurements

### Keylime Agent (Rust Implementation)
- **Primary Role**: Trusted endpoint being attested
- **Key Functions**:
  - Communicates with TPM for quotes and measurements
  - Registers with Registrar
  - Responds to Verifier attestation requests
  - Manages secure payload decryption
  - Handles revocation notifications
- **Ports**: 9002 (HTTPS), optionally ZMQ for notifications

### Keylime Registrar (Python)
- **Primary Role**: Agent enrollment and identity management
- **Key Functions**:
  - Agent registration and EK/AK validation
  - TPM credential activation challenges
  - Agent identity verification
  - Database of registered agents
- **Ports**: 8890 (HTTPS), 8891 (HTTP)

### Keylime Verifier (Python)
- **Primary Role**: Continuous attestation and policy enforcement
- **Key Functions**:
  - Continuous agent monitoring
  - Quote validation and policy checking
  - IMA runtime measurement verification
  - Revocation notification generation
  - Secure payload key management
- **Ports**: 8881 (HTTPS)

### IMA (Integrity Measurement Architecture)
- **Primary Role**: Runtime file integrity monitoring
- **Key Functions**:
  - Measures executed files and loaded modules
  - Extends measurements into PCR 10
  - Provides measurement logs for verification
  - Supports file signature verification

## Startup and Registration Workflow

```mermaid
sequenceDiagram
    participant B as Boot Process
    participant T as TPM
    participant A as Agent
    participant R as Registrar
    participant V as Verifier
    
    Note over B,T: System Boot Phase
    B->>T: UEFI measurements → PCR 0-7
    B->>T: Bootloader measurements → PCR 8-9
    B->>T: Kernel/initrd measurements → PCR 8-9
    B->>T: IMA measurements → PCR 10
    
    Note over A,T: Agent Initialization
    A->>T: Read/Generate EK (Endorsement Key)
    A->>T: Generate AK (Attestation Key)
    A->>T: Generate DevID keys (if enabled)
    
    Note over A,R: Registration Phase
    A->>R: POST /agents/{uuid} with EK, AK, certs
    R->>R: Validate EK certificate
    R->>R: Verify AK binding to EK
    R->>T: Generate activation challenge
    R->>A: Return encrypted challenge blob
    
    A->>T: TPM2_ActivateCredential(challenge)
    T->>A: Decrypted challenge response
    A->>A: Compute HMAC(key, uuid)
    A->>R: PUT /agents/{uuid} with auth_tag
    R->>R: Verify HMAC matches
    R->>A: Registration complete
    
    Note over A,V: Ready for Attestation
    A->>V: Agent available for monitoring
```

## Detailed Registration Process

### Phase 1: TPM Key Generation
```mermaid
graph LR
    subgraph "TPM Operations"
        A[Generate EK] --> B[Read EK Certificate]
        B --> C[Generate AK]
        C --> D[Generate DevID Keys]
        D --> E[Export Public Keys]
    end
    
    E --> F[Agent Registration Request]
```

### Phase 2: Registrar Validation
```mermaid
graph TB
    A[Receive Registration] --> B{Validate EK Cert?}
    B -->|No| C[Reject Registration]
    B -->|Yes| D[Verify AK Public Key]
    D --> E[Generate Challenge Nonce]
    E --> F[Encrypt with TPM2_MakeCredential]
    F --> G[Return Challenge Blob]
    G --> H[Agent Activates Credential]
    H --> I[Verify HMAC Response]
    I --> J{Valid?}
    J -->|No| C
    J -->|Yes| K[Mark Agent Active]
```

## Attestation Cycle

```mermaid
sequenceDiagram
    participant V as Verifier
    participant A as Agent
    participant T as TPM
    participant I as IMA
    
    loop Continuous Attestation (every ~30 seconds)
        V->>A: GET /quotes?nonce=X&pcrmask=Y
        A->>T: TPM2_Quote(nonce, PCR_mask, AK)
        T->>A: Quote signature + PCR values
        A->>I: Read IMA measurement log
        I->>A: Runtime measurements
        A->>V: Quote + PCRs + IMA log + event log
        
        V->>V: Validate quote signature
        V->>V: Verify PCR values against policy
        V->>V: Process IMA measurements
        V->>V: Check against runtime policy
        
        alt Attestation Success
            V->>V: Update agent status: "Get Quote"
            V->>V: Increment attestation count
        else Attestation Failure
            V->>V: Mark agent as "Invalid Quote"
            V->>A: Send revocation notification
            V->>V: Generate revocation events
        end
    end
```

## Quote Validation Process

```mermaid
graph TB
    A[Receive Quote] --> B[Verify Quote Signature]
    B --> C{Signature Valid?}
    C -->|No| D[FAIL: Invalid Quote]
    C -->|Yes| E[Extract PCR Values]
    E --> F[Validate PCR Policy]
    F --> G{PCRs Match Policy?}
    G -->|No| H[FAIL: PCR Mismatch]
    G -->|Yes| I[Process IMA Log]
    I --> J[Validate Runtime Policy]
    J --> K{IMA Valid?}
    K -->|No| L[FAIL: IMA Violation]
    K -->|Yes| M[SUCCESS: Agent Trusted]
```

## Secure Payload Provisioning

```mermaid
sequenceDiagram
    participant T as Tenant
    participant V as Verifier
    participant A as Agent
    participant TPM as TPM
    
    Note over T,V: Payload Preparation
    T->>T: Generate symmetric key K
    T->>T: Split K = U_key ⊕ V_key
    T->>T: Encrypt payload with K
    
    Note over T,A: Initial Provisioning
    T->>V: Add agent with encrypted payload
    V->>V: Store V_key and payload
    T->>A: Send U_key and encrypted payload
    A->>A: Store U_key and payload
    
    Note over V,A: Attestation-Based Decryption
    loop Attestation Success
        V->>A: Send V_key (verification key)
        A->>A: Reconstruct K = U_key ⊕ V_key
        A->>A: Decrypt payload with K
        A->>A: Extract secrets to secure mount
        A->>A: Execute autorun scripts
    end
    
    Note over V,A: Revocation Scenario
    alt Attestation Failure
        V->>V: Withhold V_key
        V->>A: Send revocation notification
        A->>A: Execute revocation actions
        A->>A: Clear sensitive data
    end
```

## Policy Enforcement Architecture

```mermaid
graph TB
    subgraph "Policy Types"
        A[TPM Policy<br/>PCR Allowlists]
        B[Runtime Policy<br/>IMA Allowlists]
        C[Measured Boot Policy<br/>UEFI Event Log]
    end
    
    subgraph "Enforcement Points"
        D[Quote Validation]
        E[IMA Log Processing]
        F[Event Log Validation]
    end
    
    subgraph "Actions"
        G[Agent Failure]
        H[Revocation Notification]
        I[Payload Withholding]
    end
    
    A --> D
    B --> E
    C --> F
    
    D --> G
    E --> G
    F --> G
    
    G --> H
    G --> I
```

## IMA Runtime Monitoring

```mermaid
graph LR
    subgraph "File System Events"
        A[File Execution]
        B[Module Loading]
        C[Firmware Loading]
    end
    
    subgraph "IMA Processing"
        D[Measure File Hash]
        E[Check Signature]
        F[Extend PCR 10]
        G[Log Entry]
    end
    
    subgraph "Verification"
        H[Runtime Policy Check]
        I[Signature Validation]
        J[Allowlist Lookup]
    end
    
    A --> D
    B --> D
    C --> D
    
    D --> E
    E --> F
    F --> G
    
    G --> H
    G --> I
    G --> J
```

## Certificate and Key Management

```mermaid
graph TB
    subgraph "TPM Keys"
        A[EK - Endorsement Key<br/>TPM Identity]
        B[AK - Attestation Key<br/>Quote Signing]
        C[DevID Keys<br/>Device Identity]
    end
    
    subgraph "Keylime Certificates"
        D[Agent mTLS Cert<br/>Communication Security]
        E[Revocation Cert<br/>Notification Signing]
        F[CA Certificates<br/>Trust Chain]
    end
    
    subgraph "Key Operations"
        G[Registration Challenge]
        H[Quote Signing]
        I[Payload Encryption]
        J[Revocation Signing]
    end
    
    A --> G
    B --> H
    D --> I
    E --> J
```

## Network Communication Flows

```mermaid
graph TB
    subgraph "Agent Communications"
        A[Agent:9002 HTTPS<br/>Quote Requests]
        B[Agent ZMQ<br/>Revocation Listening]
    end
    
    subgraph "Registrar APIs"
        C[Registrar:8890 HTTPS<br/>Registration API]
        D[Registrar:8891 HTTP<br/>Status/Management]
    end
    
    subgraph "Verifier APIs"
        E[Verifier:8881 HTTPS<br/>Tenant API]
        F[Verifier Internal<br/>Agent Monitoring]
    end
    
    A <--> F
    C <--> A
    E <--> A
    E <--> C
```

## Attack Surface Analysis

### 1. Network Attack Vectors

```mermaid
graph TB
    subgraph "Network Threats"
        A[Man-in-the-Middle]
        B[Eavesdropping]
        C[Replay Attacks]
        D[DoS/DDoS]
    end
    
    subgraph "Mitigations"
        E[mTLS Encryption]
        F[Certificate Validation]
        G[Nonce-based Freshness]
        H[Rate Limiting]
    end
    
    A -.-> E
    B -.-> E
    C -.-> G
    D -.-> H
```

### 2. TPM Attack Vectors

```mermaid
graph TB
    subgraph "TPM Threats"
        A[Physical Attacks]
        B[Side Channel Analysis]
        C[Firmware Vulnerabilities]
        D[Reset Attacks]
    end
    
    subgraph "Protections"
        E[Tamper Resistance]
        F[Hardware Countermeasures]
        G[Secure Boot Chain]
        H[Anti-Rollback]
    end
    
    A -.-> E
    B -.-> F
    C -.-> G
    D -.-> H
```

### 3. Software Attack Vectors

```mermaid
graph TB
    subgraph "Software Threats"
        A[Agent Compromise]
        B[IMA Bypass]
        C[Policy Manipulation]
        D[Key Extraction]
    end
    
    subgraph "Detection Methods"
        E[Continuous Attestation]
        F[Quote Validation]
        G[Policy Enforcement]
        H[Hardware Key Storage]
    end
    
    A -.-> E
    B -.-> F
    C -.-> G
    D -.-> H
```

## Potential Vulnerability Areas

### High-Risk Components:
1. **Agent-Verifier Communication**
   - Quote replay attacks
   - Network protocol vulnerabilities
   - Certificate validation bypasses

2. **TPM Integration**
   - TPM firmware vulnerabilities
   - Key extraction attacks
   - Reset/rollback attacks

3. **Policy Enforcement**
   - IMA bypass techniques
   - Runtime policy manipulation
   - Measurement log tampering

4. **Registrar Security**
   - Registration flooding
   - Identity spoofing
   - Challenge response manipulation

### Medium-Risk Areas:
1. **Secure Payload Handling**
   - Key reconstruction timing
   - Memory-resident key exposure
   - Payload decryption side-channels

2. **Revocation Mechanisms**
   - Revocation notification delivery
   - Action execution reliability
   - Certificate revocation timing

### Testing Recommendations:
1. **Fuzzing Network Protocols**: Test all REST API endpoints
2. **TPM Stress Testing**: Verify behavior under unusual TPM states
3. **IMA Bypass Research**: Test various kernel-level bypass techniques
4. **Timing Analysis**: Look for side-channel vulnerabilities
5. **Policy Manipulation**: Test robustness of policy parsing and enforcement

This analysis provides a comprehensive foundation for understanding Keylime's architecture and identifying potential security research areas for your thesis.
