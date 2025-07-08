# Keylime Architecture and Workflow Analysis

## Table of Contents
1. [Overall System Architecture](#overall-system-architecture)
2. [Component Interaction Diagrams](#component-interaction-diagrams)
3. [Startup and Registration Workflow](#startup-and-registration-workflow)
4. [Attestation Cycle](#attestation-cycle)
5. [Secure Payload Provisioning](#secure-payload-provisioning)
6. [Policy Enforcement and Revocation](#policy-enforcement-and-revocation)
7. [Attack Surface Analysis](#attack-surface-analysis)

## Overall System Architecture - Docker Deployment

```mermaid
graph TB
    subgraph "Host System"
        HOST[Host Linux System]
        DOCKER[Docker Engine]
        NETWORK[Docker Network]
        VOLUME[keylime-data Volume]
    end
    
    subgraph "keylime-registrar Container"
        REG[Keylime Registrar\nPython Service]
        REG_PORT1[":8890 Registration API"]
        REG_PORT2[":8891 Management API"]
    end
    
    subgraph "keylime-verifier Container"
        VER[Keylime Verifier\nPython Service]
        VER_PORT1[":8880 Internal API"]
        VER_PORT2[":8881 Tenant API"]
        POLICY[Runtime Policies\n& Configuration]
    end
    
    subgraph "keylime-agent Container"
        AGENT[Keylime Agent\nRust Binary]
        SWTPM[Software TPM 2.0\nEmulator]
        ABRMD[TPM2-ABRMD\nResource Manager]
        DBUS[D-Bus System]
        IMA[IMA/EVM\nKernel Subsystem]
    end
    
    subgraph "keylime-tenant Container"
        TENANT[Keylime Tenant CLI\nPython Tool]
    end
    
    %% Container relationships
    HOST --> DOCKER
    DOCKER --> NETWORK
    DOCKER --> VOLUME
    
    %% Network connections between containers
    AGENT <--> REG
    AGENT <--> VER
    TENANT <--> REG
    TENANT <--> VER
    VER <--> POLICY
    
    %% TPM stack within agent container
    AGENT <--> ABRMD
    ABRMD <--> SWTPM
    AGENT <--> DBUS
    AGENT <--> IMA
    IMA -.-> SWTPM
    
    %% Shared storage
    REG <--> VOLUME
    VER <--> VOLUME
    AGENT <--> VOLUME
    TENANT <--> VOLUME
    
    %% Host port mappings
    REG_PORT1 -.-> |Host:8890| HOST
    REG_PORT2 -.-> |Host:8891| HOST
    VER_PORT1 -.-> |Host:8880| HOST
    VER_PORT2 -.-> |Host:8881| HOST
    
    style SWTPM fill:#ff9999
    style AGENT fill:#9999ff
    style VER fill:#ffff99
    style REG fill:#ff99ff
    style VOLUME fill:#cccccc
```

## Component Roles and Responsibilities (Docker Deployment)

### Software TPM (swtpm)
- **Primary Role**: Emulated Hardware Root of Trust
- **Key Functions**:
  - Emulates TPM 2.0 functionality in software
  - Stores cryptographic keys (EK, AK, DevID keys)
  - Generates attestation quotes
  - Maintains Platform Configuration Registers (PCRs)
  - Provides secure key storage and cryptographic operations
- **Configuration**: 
  - State directory: `/tmp/tpmdir` (ephemeral)
  - TCP ports: 2321 (data), 2322 (control)
  - Started with `swtpm_setup --tpm2 --createek --create-platform-cert`

### TPM2-ABRMD (TPM Resource Manager)
- **Primary Role**: TPM access broker and resource manager
- **Key Functions**:
  - Manages concurrent TPM access between processes
  - Handles TPM context management
  - Provides TCTI interface to applications
  - Manages TPM sessions and handles
- **Configuration**:
  - TCTI: `tabrmd:bus_type=system`
  - Connects to swtpm via `--tcti=swtpm:`
  - Runs with `--allow-root --flush-all`

### Keylime Agent Container (keylime-agent)
- **Primary Role**: Containerized trusted endpoint
- **Key Functions**:
  - Runs Rust-based keylime agent (`/usr/bin/keylime_agent`)
  - Communicates with software TPM via ABRMD
  - Registers with registrar container
  - Responds to verifier attestation requests
  - Manages secure payload decryption (if enabled)
  - Handles revocation notifications
- **Configuration**:
  - Privileged container with root access
  - Debug logging: `RUST_LOG=keylime_agent=debug,keylime=debug`
  - Secure mount disabled: `RUST_KEYLIME_SKIP_SECURE_MOUNT=1`
  - Registrar discovery: DNS lookup for 'registrar' container

### Keylime Registrar Container (keylime-registrar)
- **Primary Role**: Containerized agent enrollment service
- **Key Functions**:
  - Agent registration and EK/AK validation
  - TPM credential activation challenges
  - Agent identity verification
  - Database of registered agents
- **Network Configuration**:
  - Internal ports: 8890 (registration), 8891 (management)
  - Host ports: 8890:8890, 8891:8891
  - Container name: `keylime-registrar`
  - Environment: `KEYLIME_REGISTRAR_IP=0.0.0.0`

### Keylime Verifier Container (keylime-verifier)
- **Primary Role**: Containerized attestation verification service
- **Key Functions**:
  - Continuous agent monitoring
  - Quote validation and policy checking
  - IMA runtime measurement verification
  - Revocation notification generation
  - Secure payload key management
- **Network Configuration**:
  - Internal ports: 8880 (internal), 8881 (tenant API)
  - Host ports: 8880:8880, 8881:8881
  - Container name: `keylime-verifier`
  - Environment: `KEYLIME_VERIFIER_IP=0.0.0.0`

### Keylime Tenant Container (keylime-tenant)
- **Primary Role**: Management and policy interface
- **Key Functions**:
  - Command-line interface for agent management
  - Policy configuration and deployment
  - Agent enrollment and monitoring
  - Payload provisioning (when enabled)
- **Configuration**:
  - Runs on-demand (not continuously)
  - Accesses other containers via Docker network
  - Shares keylime-data volume for persistence

### IMA (Integrity Measurement Architecture)
- **Primary Role**: Runtime file integrity monitoring within agent container
- **Key Functions**:
  - Measures executed files and loaded modules
  - Extends measurements into TPM PCR 10
  - Provides measurement logs for verification
  - Supports file signature verification
- **Container Context**: Runs within agent container's kernel namespace

## Startup and Registration Workflow (Docker Deployment)

```mermaid
sequenceDiagram
    participant HOST as Host System
    participant DC as Docker Compose
    participant REG as keylime-registrar
    participant VER as keylime-verifier
    participant AGENT as keylime-agent
    participant SWTPM as Software TPM
    participant ABRMD as TPM2-ABRMD
    
    HOST->>DC: docker-compose up
    
    Note over DC,REG: Infrastructure Startup
    DC->>REG: Start registrar container
    REG->>REG: Initialize Python service
    REG->>REG: Listen on :8890, :8891
    REG->>REG: Load keylime-data volume
    
    DC->>VER: Start verifier container (depends_on: registrar)
    VER->>VER: Initialize Python service
    VER->>VER: Listen on :8880, :8881
    VER->>VER: Load keylime-data volume
    VER->>REG: Verify registrar dependency
    
    Note over DC,AGENT: Agent Container Startup
    DC->>AGENT: Start agent container (privileged)
    AGENT->>AGENT: Create directories: /tmp/tpmdir, /var/lib/keylime
    AGENT->>AGENT: Create keylime user, tss group
    AGENT->>AGENT: Set directory permissions
    AGENT->>AGENT: Start dbus-daemon --system
    
    Note over AGENT,SWTPM: TPM Emulation Setup
    AGENT->>SWTPM: swtpm_setup --tpm2 --tpmstate /tmp/tpmdir
    SWTPM->>SWTPM: Create EK certificate, platform cert
    AGENT->>SWTPM: swtpm socket --tpm2 (ports 2321/2322)
    SWTPM->>SWTPM: Start TPM emulator daemon
    
    Note over AGENT,ABRMD: TPM Resource Manager
    AGENT->>ABRMD: tpm2-abrmd --tcti=swtpm --allow-root --flush-all
    ABRMD->>SWTPM: Connect to TPM emulator
    
    Note over AGENT,REG: Service Discovery
    AGENT->>REG: getent hosts registrar (DNS resolution)
    AGENT->>REG: nc -z registrar 8891 (port availability)
    
    Note over AGENT,REG: Agent Registration
    AGENT->>AGENT: exec /usr/bin/keylime_agent
    AGENT->>ABRMD: Connect via TCTI=tabrmd:bus_type=system
    AGENT->>SWTPM: Read/Generate EK (Endorsement Key)
    AGENT->>SWTPM: Generate AK (Attestation Key)
    AGENT->>REG: POST /agents/{uuid} with EK, AK, certs
    
    REG->>REG: Validate EK certificate
    REG->>REG: Verify AK binding to EK
    REG->>REG: Generate activation challenge
    REG->>AGENT: Return encrypted challenge blob
    
    AGENT->>ABRMD: TPM2_ActivateCredential(challenge)
    ABRMD->>SWTPM: Execute TPM command
    SWTPM->>ABRMD: Decrypted challenge response
    ABRMD->>AGENT: Return decrypted credential
    AGENT->>AGENT: Compute HMAC(key, uuid)
    AGENT->>REG: PUT /agents/{uuid} with auth_tag
    REG->>REG: Verify HMAC matches
    REG->>AGENT: Registration complete
    
    Note over AGENT,VER: Ready for Attestation
    AGENT->>VER: Agent available for monitoring
    VER->>AGENT: Begin continuous attestation cycle
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

## Attestation Cycle (Docker Deployment)

```mermaid
sequenceDiagram
    participant VER as keylime-verifier
    participant AGENT as keylime-agent
    participant ABRMD as TPM2-ABRMD
    participant SWTPM as Software TPM
    participant IMA as IMA Subsystem
    
    loop Continuous Attestation (every ~30 seconds)
        VER->>AGENT: GET /quotes?nonce=X&pcrmask=Y
        Note over AGENT,SWTPM: Quote Generation
        AGENT->>ABRMD: TPM2_Quote(nonce, PCR_mask, AK)
        ABRMD->>SWTPM: Execute TPM command
        SWTPM->>ABRMD: Quote signature + PCR values
        ABRMD->>AGENT: Return quote data
        
        Note over AGENT,IMA: IMA Log Collection
        AGENT->>IMA: Read IMA measurement log
        IMA->>AGENT: Runtime measurements since last check
        
        Note over AGENT,VER: Response Assembly
        AGENT->>VER: Quote + PCRs + IMA log + event log
        
        Note over VER,VER: Validation Process
        VER->>VER: Validate quote signature with stored AK
        VER->>VER: Verify nonce freshness
        VER->>VER: Check PCR values against policy
        VER->>VER: Process IMA measurements
        VER->>VER: Check against runtime policy
        
        alt Attestation Success
            VER->>VER: Update agent status: "Get Quote"
            VER->>VER: Increment attestation count
            VER->>VER: Log successful attestation
        else Attestation Failure
            VER->>VER: Mark agent as "Invalid Quote"
            VER->>AGENT: Send revocation notification
            VER->>VER: Generate revocation events
            VER->>VER: Log failure details
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
        A[TPM Policy\nPCR Allowlists]
        B[Runtime Policy\nIMA Allowlists]
        C[Measured Boot Policy\nUEFI Event Log]
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
        A[EK - Endorsement Key\nTPM Identity]
        B[AK - Attestation Key\nQuote Signing]
        C[DevID Keys\nDevice Identity]
    end
    
    subgraph "Keylime Certificates"
        D[Agent mTLS Cert\nCommunication Security]
        E[Revocation Cert\nNotification Signing]
        F[CA Certificates\nTrust Chain]
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

## Network Communication Flows (Docker Deployment)

```mermaid
graph TB
    subgraph "Host Network Interface"
        HOST_8890[Host:8890\nRegistrar API]
        HOST_8891[Host:8891\nRegistrar Mgmt]
        HOST_8880[Host:8880\nVerifier Internal]
        HOST_8881[Host:8881\nVerifier Tenant]
    end
    
    subgraph "Docker Network (keylime-network)"
        subgraph "keylime-registrar"
            REG_8890[":8890 Registration API"]
            REG_8891[":8891 Management API"]
        end
        
        subgraph "keylime-verifier"
            VER_8880[":8880 Internal API"]
            VER_8881[":8881 Tenant API"]
        end
        
        subgraph "keylime-agent"
            AGENT_9002[":9002 HTTPS (default)"]
            AGENT_TPM[TPM Stack\nswtpm + abrmd"]
        end
        
        subgraph "keylime-tenant"
            TENANT_CLI[Tenant CLI\nOn-demand]
        end
    end
    
    subgraph "Shared Storage"
        VOLUME[keylime-data Volume\n/var/lib/keylime]
    end
    
    %% Host port mappings
    HOST_8890 --> REG_8890
    HOST_8891 --> REG_8891
    HOST_8880 --> VER_8880
    HOST_8881 --> VER_8881
    
    %% Inter-container communication
    AGENT_9002 <--> VER_8880
    AGENT_9002 <--> REG_8890
    TENANT_CLI <--> VER_8881
    TENANT_CLI <--> REG_8891
    
    %% Shared storage access
    REG_8890 <--> VOLUME
    VER_8880 <--> VOLUME
    AGENT_9002 <--> VOLUME
    TENANT_CLI <--> VOLUME
    
    %% TPM access within agent
    AGENT_9002 <--> AGENT_TPM
    
    style HOST_8890 fill:#e1f5fe
    style HOST_8891 fill:#e1f5fe
    style HOST_8880 fill:#e1f5fe
    style HOST_8881 fill:#e1f5fe
    style VOLUME fill:#f3e5f5
```

## Attack Surface Analysis (Docker Deployment)

### 1. Container-Specific Attack Vectors

```mermaid
graph TB
    subgraph "Container Breakout Threats"
        A[Privileged Container Escape]
        B[Volume Mount Exploitation]
        C[Network Namespace Bypass]
        D[Process Injection]
    end
    
    subgraph "Software TPM Threats"
        E[TPM Emulation Bypass]
        F[State Directory Manipulation]
        G[ABRMD Resource Manager Attacks]
        H[D-Bus Interface Exploitation]
    end
    
    subgraph "Inter-Container Communication"
        I[Container Name Spoofing]
        J[Docker Network MITM]
        K[Volume Race Conditions]
        L[Service Discovery Poisoning]
    end
    
    subgraph "Mitigations"
        M[Container Security Policies]
        N[Volume Permission Controls]
        O[Network Segmentation]
        P[Process Monitoring]
    end
    
    A -.-> M
    B -.-> N
    C -.-> O
    D -.-> P
    E -.-> M
    F -.-> N
    G -.-> P
    H -.-> O
    I -.-> O
    J -.-> O
    K -.-> N
    L -.-> P
```

### 2. Docker-Specific TPM Attack Vectors

```mermaid
graph TB
    subgraph "Software TPM Limitations"
        A[No Hardware Security]
        B[Filesystem-Based State]
        C[Process-Level Isolation Only]
        D[Ephemeral TPM State]
    end
    
    subgraph "Container Runtime Threats"
        E[Container Restart Attacks]
        F[Volume Persistence Issues]
        G[Network Isolation Bypass]
        H[Host System Access]
    end
    
    subgraph "Enhanced Detection"
        I[Container Monitoring]
        J[Volume Integrity Checks]
        K[Network Traffic Analysis]
        L[Process Behavior Monitoring]
    end
    
    A -.-> I
    B -.-> J
    C -.-> K
    D -.-> L
    E -.-> I
    F -.-> J
    G -.-> K
    H -.-> L
```

### 3. Container Network Attack Vectors

```mermaid
graph TB
    subgraph "Network Threats"
        A[Container Network MITM]
        B[Service Name Spoofing]
        C[Port Scanning/Discovery]
        D[DNS Poisoning]
    end
    
    subgraph "Docker-Specific Mitigations"
        E[Container Network Policies]
        F[Service Mesh Implementation]
        G[Container-to-Container mTLS]
        H[Network Monitoring]
    end
    
    A -.-> E
    B -.-> F
    C -.-> G
    D -.-> H
```

## Potential Vulnerability Areas (Docker Deployment)

### High-Risk Components:
1. **Container-to-Container Communication**
   - Service name spoofing attacks
   - Docker network MITM vulnerabilities
   - Container escape to host system
   - Volume mount exploitation

2. **Software TPM Implementation**
   - TPM emulation bypass techniques
   - Filesystem-based state manipulation
   - ABRMD resource manager vulnerabilities
   - D-Bus interface exploitation

3. **Agent Container Security**
   - Privileged container escape
   - Process injection into agent
   - Configuration file tampering
   - Debug log information leakage

4. **Shared Volume Security**
   - Race conditions in keylime-data volume
   - Cross-container data access
   - Permission escalation via shared files
   - Persistent state corruption

### Medium-Risk Areas:
1. **Docker Network Security**
   - Network namespace bypass
   - Container network discovery
   - Inter-container traffic analysis
   - Service discovery poisoning

2. **Container Runtime Security**
   - Container restart timing attacks
   - Environment variable exposure
   - Resource exhaustion attacks
   - Container image supply chain

### Docker-Specific Testing Recommendations:
1. **Container Security Testing**
   - Test container escape scenarios
   - Verify volume mount security
   - Check network isolation effectiveness
   - Validate process isolation boundaries

2. **Software TPM Testing**
   - Test TPM emulation bypass techniques
   - Verify state persistence security
   - Check ABRMD resource management
   - Test D-Bus interface security

3. **Inter-Container Communication Testing**
   - Test service name spoofing
   - Verify network traffic encryption
   - Check container-to-container authentication
   - Test shared volume access controls

4. **Configuration Security Testing**
   - Test configuration file injection
   - Verify environment variable security
   - Check secrets management
   - Test debug mode information leakage

### Docker Deployment Security Considerations:
1. **Use non-privileged containers** when possible
2. **Implement network policies** for container communication
3. **Use secrets management** for sensitive configuration
4. **Monitor container runtime** for anomalous behavior
5. **Implement container image scanning** for vulnerabilities
6. **Use read-only filesystems** where applicable
7. **Implement proper logging and monitoring** for container activities
