# Keylime Docker Deployment Architecture - Based on Your Configuration

## Docker Compose Setup

Based on `docker-compose.yml` files, here's the **actual** deployment architecture:

```mermaid
graph TB
    subgraph "Docker Network"
        subgraph "keylime-registrar Container"
            REG[Keylime Registrar<br/>Python Service]
            REG_PORT1[":8890 Registration"]
            REG_PORT2[":8891 Status/Mgmt"]
        end
        
        subgraph "keylime-verifier Container"
            VER[Keylime Verifier<br/>Python Service]
            VER_PORT1[":8880 Internal"]
            VER_PORT2[":8881 Tenant API"]
        end
        
        subgraph "keylime-agent Container"
            AGENT[Keylime Agent<br/>Rust Binary]
            SWTPM[Software TPM<br/>Emulator]
            ABRMD[TPM2-ABRMD<br/>Resource Manager]
            DBUS[D-Bus System]
        end
        
        subgraph "keylime-tenant Container"
            TENANT[Keylime Tenant<br/>CLI Tool]
        end
        
        subgraph "Shared Storage"
            VOLUME[keylime-data<br/>Docker Volume]
        end
    end
    
    %% Network connections
    AGENT <--> REG
    AGENT <--> VER
    TENANT <--> REG
    TENANT <--> VER
    
    %% TPM stack in agent
    AGENT <--> ABRMD
    ABRMD <--> SWTPM
    AGENT <--> DBUS
    
    %% Shared storage
    REG <--> VOLUME
    VER <--> VOLUME
    AGENT <--> VOLUME
    TENANT <--> VOLUME
    
    %% Port mappings to host
    REG_PORT1 -.-> |Host:8890| HOST1[Host System]
    REG_PORT2 -.-> |Host:8891| HOST1
    VER_PORT1 -.-> |Host:8880| HOST1
    VER_PORT2 -.-> |Host:8881| HOST1
    
    style SWTPM fill:#ff9999
    style AGENT fill:#9999ff
    style VER fill:#ffff99
    style REG fill:#ff99ff
```

## Agent Container Startup Sequence

```mermaid
sequenceDiagram
    participant DC as Docker Compose
    participant AC as Agent Container
    participant SWTPM as Software TPM
    participant ABRMD as TPM2-ABRMD
    participant DBUS as D-Bus
    participant REG as Registrar Container
    participant AGENT as Keylime Agent
    
    DC->>AC: Start keylime-agent container
    AC->>AC: Create /tmp/tpmdir, /var/lib/keylime
    AC->>AC: Create keylime user & tss group
    AC->>AC: Set permissions on directories
    
    Note over AC,DBUS: System Service Setup
    AC->>DBUS: Start dbus-daemon --system
    
    Note over AC,SWTPM: TPM Emulator Setup
    AC->>SWTPM: swtpm_setup --tpm2 --tpmstate /tmp/tpmdir
    AC->>SWTPM: Create EK, platform certificates
    AC->>SWTPM: swtpm socket --tpm2 (port 2321/2322)
    
    Note over AC,ABRMD: TPM Resource Manager
    AC->>ABRMD: tpm2-abrmd --tcti=swtpm --allow-root
    ABRMD->>SWTPM: Connect to TPM emulator
    
    Note over AC,REG: Service Discovery
    AC->>REG: getent hosts registrar (DNS check)
    AC->>REG: nc -z registrar 8891 (port check)
    
    Note over AC,AGENT: Agent Startup
    AC->>AGENT: exec /usr/bin/keylime_agent
    AGENT->>ABRMD: Connect to TPM via ABRMD
    AGENT->>REG: Begin registration process
```

## Corrected Component Communication

### Network Configuration
- **Container Names**: `keylime-registrar`, `keylime-verifier`, `keylime-agent`, `keylime-tenant`
- **Internal Communication**: Containers communicate via container names
- **Host Access**: Only registrar and verifier expose ports to host

### TPM Configuration
- **Software TPM**: Uses `swtpm` emulator, not hardware TPM
- **TPM Resource Manager**: Uses `tpm2-abrmd` for TPM access
- **TPM State**: Stored in `/tmp/tpmdir` (ephemeral)

### Agent Configuration
- **Rust Implementation**: Uses `/usr/bin/keylime_agent` (Rust binary)
- **Debug Mode**: `RUST_LOG=keylime_agent=debug,keylime=debug`
- **Secure Mount**: Disabled with `RUST_KEYLIME_SKIP_SECURE_MOUNT=1`

## Updated Sequence Diagram Based on Your Setup

```mermaid
sequenceDiagram
    participant HOST as Host System
    participant DC as Docker Compose
    participant REG as keylime-registrar
    participant VER as keylime-verifier
    participant AGENT as keylime-agent
    participant SWTPM as Software TPM
    
    HOST->>DC: docker-compose up
    
    Note over DC,REG: Start Infrastructure
    DC->>REG: Start registrar container
    REG->>REG: Listen on :8890, :8891
    
    DC->>VER: Start verifier container
    VER->>VER: Listen on :8880, :8881
    VER->>REG: Wait for registrar dependency
    
    Note over DC,AGENT: Start Agent
    DC->>AGENT: Start agent container
    AGENT->>SWTPM: Initialize software TPM
    SWTPM->>SWTPM: Create TPM state in /tmp/tpmdir
    AGENT->>AGENT: Start tpm2-abrmd
    
    Note over AGENT,REG: Registration
    AGENT->>REG: DNS lookup for 'registrar'
    AGENT->>REG: Port check nc -z registrar 8891
    AGENT->>REG: Start keylime_agent process
    AGENT->>SWTPM: Generate EK/AK keys
    AGENT->>REG: Register with keys
    
    Note over HOST,VER: Management Access
    HOST->>VER: Access tenant API on :8881
    HOST->>REG: Access management on :8891
```
