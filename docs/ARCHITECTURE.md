# HoneyBee Node Architecture

## Overview

The HoneyBee Node is designed with a modular, production-ready architecture following Go best practices. This document describes the internal structure and design decisions.

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    HoneyBee Node                        │
├─────────────────────────────────────────────────────────┤
│  cmd/node/main.go                                       │
│  ├── Configuration Loading                              │
│  ├── Logger Initialization                              │
│  ├── Signal Handling                                    │
│  └── Client Lifecycle Management                        │
└─────────────────────────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────┐
│              Internal Packages                          │
├─────────────────────────────────────────────────────────┤
│  internal/                                              │
│  ├── client/      (Core client logic)                   │
│  ├── protocol/    (Message definitions)                 │
│  ├── auth/        (TLS & TOTP)                          │
│  ├── config/      (Configuration management)            │
│  └── logger/      (Structured logging)                  │
└─────────────────────────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────┐
│               External Dependencies                      │
├─────────────────────────────────────────────────────────┤
│  • crypto/tls         (TLS 1.3 encryption)              │
│  • github.com/pquerna/otp  (TOTP authentication)        │
│  • github.com/sirupsen/logrus  (Structured logging)     │
│  • gopkg.in/yaml.v3   (Configuration parsing)           │
└─────────────────────────────────────────────────────────┘
```

## Component Details

### 1. Main Entry Point (`cmd/node/main.go`)

**Responsibilities:**
- Parse command-line flags
- Load configuration
- Initialize logger
- Create and start node client
- Handle graceful shutdown signals

**Design Pattern:** Command pattern with signal handling

```go
main()
  ├── Parse flags
  ├── Load config
  ├── Init logger
  ├── Create client
  ├── Setup signals
  └── Run/Stop client
```

### 2. Client Package (`internal/client/`)

**Core Component:** `NodeClient` struct

```go
type NodeClient struct {
    cfg        *config.Config
    nodeID     uint64
    totpMgr    *auth.TOTPManager
    tlsConfig  *tls.Config
    conn       net.Conn
    writer     *bufio.Writer
    reader     *bufio.Reader
    mu         sync.Mutex
    stopChan   chan struct{}
    doneChan   chan struct{}
    registered bool
}
```

**State Machine:**

```
[Start] → [Connecting] → [Registering] → [Running] → [Stopped]
            ↑               ↓                ↓
            └───────────────┴────────────────┘
                    (Reconnect on error)
```

**Key Methods:**
- `Run()`: Main event loop
- `connect()`: Establish TLS connection
- `register()`: Send registration with TOTP
- `eventLoop()`: Handle heartbeats and messages
- `handleMessage()`: Process incoming commands

**Concurrency Model:**
- Main goroutine: Connection management
- Reader goroutine: Read incoming messages
- Heartbeat ticker: Send periodic status updates
- Channel-based synchronization

### 3. Protocol Package (`internal/protocol/`)

**Purpose:** Define all protocol messages and constants

**Key Types:**
- `MessageEnvelope`: Generic wrapper with version
- `NodeRegistration`: Initial handshake message
- `NodeStatusUpdate`: Heartbeat message
- `NodeEvent`: Event notification
- `NodeCommand`: Commands from manager
- `RegistrationAck`: Registration response

**Design Pattern:** Enum-based message types with JSON serialization

```go
type MessageEnvelope struct {
    Version uint64
    Message MessageType
}

type MessageType struct {
    NodeRegistration *NodeRegistration
    NodeStatusUpdate *NodeStatusUpdate
    NodeEvent        *NodeEvent
    NodeCommand      *NodeCommand
    ...
}
```

### 4. Authentication Package (`internal/auth/`)

#### TLS Module (`tls.go`)

**Features:**
- TLS 1.3 with strong cipher suites
- Certificate loading and validation
- Mutual TLS support
- Configurable verification

**Security Defaults:**
```go
MinVersion: tls.VersionTLS13
CipherSuites: [
    TLS_AES_256_GCM_SHA384,
    TLS_AES_128_GCM_SHA256,
    TLS_CHACHA20_POLY1305_SHA256,
]
```

#### TOTP Module (`totp.go`)

**Features:**
- Secret generation and storage
- Code generation and validation
- Persistent storage with proper permissions
- RFC 6238 compliant

**Secret Storage:**
```
~/.config/honeybee/.honeybee_totp_secret
Permissions: 0600 (owner read/write only)
```

**TOTP Parameters:**
- Algorithm: SHA-1 (RFC standard)
- Digits: 6
- Period: 30 seconds
- Secret: 20 bytes (160 bits)

### 5. Configuration Package (`internal/config/`)

**Features:**
- YAML-based configuration
- Validation on load
- Default value generation
- Type-safe access

**Configuration Hierarchy:**
```
Config
├── NodeConfig
│   ├── Name
│   ├── Type
│   ├── Address
│   └── Port
├── ServerConfig
│   ├── Address
│   ├── HeartbeatInterval
│   ├── ReconnectDelay
│   └── ConnectionTimeout
├── TLSConfig
│   ├── Enabled
│   ├── CertFile
│   ├── KeyFile
│   ├── CAFile
│   ├── InsecureSkipVerify
│   └── ServerName
├── AuthConfig
│   ├── TOTPEnabled
│   └── TOTPSecretDir
└── LogConfig
    ├── Level
    ├── Format
    └── File
```

### 6. Logger Package (`internal/logger/`)

**Features:**
- Structured logging with logrus
- Multiple output formats (text, JSON)
- Configurable log levels
- File and stdout output

**Log Levels:**
```
Debug → Info → Warn → Error → Fatal
```

**Field-based Logging:**
```go
logger.WithFields(map[string]interface{}{
    "node_id": nodeID,
    "event": "registration",
}).Info("Node registered")
```

## Communication Flow

### Connection Establishment

```
1. [Node] Create TCP/TLS connection
2. [Node] → [Manager]: NodeRegistration (with TOTP)
3. [Manager] → [Node]: RegistrationAck
4. [Node] → [Manager]: NodeStatusUpdate (Running)
5. [Node] Enter event loop
```

### Event Loop

```
Loop:
  Select:
    ├── Heartbeat timer expires → Send NodeStatusUpdate
    ├── Message received → Handle NodeCommand
    └── Stop signal → Send NodeDrop and exit
```

### Message Processing

```
Incoming Message
  ↓
Parse JSON Envelope
  ↓
Validate Protocol Version
  ↓
Extract Message Type
  ↓
Switch on Message Type
  ├── NodeCommand → Execute command
  └── Other → Log warning
```

## Error Handling Strategy

### Connection Errors

```
Error Detected
  ↓
Close Connection
  ↓
Log Error
  ↓
Wait Reconnect Delay
  ↓
Retry Connection
```

### Protocol Errors

```
Invalid Message
  ↓
Log Warning
  ↓
Continue (Don't disconnect)
```

### Fatal Errors

```
Configuration Error
  ↓
Log Fatal
  ↓
Exit(1)
```

## Security Architecture

### Defense in Depth

```
Layer 1: Network (Firewall, VPN)
  ↓
Layer 2: TLS 1.3 Encryption
  ↓
Layer 3: Certificate Verification
  ↓
Layer 4: TOTP Authentication
  ↓
Layer 5: Application Logic
```

### Secret Management

```
TOTP Secret
  ├── Generation: crypto/rand (20 bytes)
  ├── Storage: ~/.config/honeybee/
  ├── Permissions: 0600
  └── Encoding: Base32
```

### Certificate Chain

```
CA Certificate
  ├── Server Certificate
  │   └── Used by Manager
  └── Client Certificate (optional)
      └── Used by Node (mutual TLS)
```

## Performance Considerations

### Connection Management

- **Buffered I/O**: Uses `bufio.Reader/Writer` for efficient I/O
- **Connection Pooling**: Single persistent connection (not pooled)
- **Timeouts**: Configurable connection timeout
- **Keepalive**: TCP keepalive enabled

### Memory Usage

- **Fixed Buffers**: Pre-allocated read/write buffers
- **No Memory Leaks**: Proper cleanup on disconnect
- **Goroutine Management**: Controlled goroutine lifecycle

### CPU Usage

- **Minimal Idle CPU**: Select-based event loop
- **Efficient Serialization**: Standard library JSON
- **No Busy Waiting**: Channel and timer-based

## Extensibility

### Adding New Message Types

1. Define in `internal/protocol/protocol.go`
2. Add to `MessageType` struct
3. Implement handler in `client.handleMessage()`
4. Update documentation

### Adding New Authentication Methods

1. Create new module in `internal/auth/`
2. Implement authentication interface
3. Integrate in client registration
4. Update configuration

### Adding Metrics

1. Add metrics package
2. Instrument critical paths
3. Export via HTTP endpoint (Prometheus)
4. Update documentation

## Testing Strategy

### Unit Tests

- Test individual functions
- Mock external dependencies
- Table-driven tests

### Integration Tests

- Test with real manager
- Test TLS handshake
- Test TOTP flow

### End-to-End Tests

- Deploy in test environment
- Validate full lifecycle
- Test failure scenarios

## Deployment Models

### 1. Standalone Binary

```
Binary → Config File → Certs → Logs
```

### 2. Systemd Service

```
systemd → Binary → Config → Certs → Logs
```

### 3. Docker Container

```
Docker → Image → Volume Mounts
           ├── Config
           ├── Certs
           └── Logs
```

### 4. Kubernetes Pod

```
K8s → Deployment → Pod
        ├── ConfigMap (config)
        ├── Secret (certs)
        └── PersistentVolume (TOTP)
```

## Future Enhancements

1. **Metrics Export**: Prometheus endpoint
2. **Health Endpoint**: HTTP health check
3. **Hot Reload**: Config reload without restart
4. **Plugin System**: Pluggable honeypot modules
5. **Rate Limiting**: Configurable rate limits
6. **Compression**: Optional message compression
7. **Multiple Managers**: Connect to multiple managers
8. **Backup Manager**: Failover support

## Design Decisions

### Why Go?

- Excellent concurrency support
- Strong standard library
- Easy deployment (single binary)
- Great performance
- Good security libraries

### Why Internal Packages?

- Prevents external import
- Clear API boundaries
- Better encapsulation
- Standard Go practice

### Why Structured Logging?

- Machine-parseable logs
- Better debugging
- Integration with log aggregators
- Production-ready

### Why TOTP?

- Standard protocol (RFC 6238)
- Time-based security
- No shared secrets over wire
- Revocable authentication

### Why TLS 1.3?

- Best security
- Reduced latency
- Forward secrecy
- Industry standard

## References

- [Go Project Layout](https://github.com/golang-standards/project-layout)
- [Effective Go](https://golang.org/doc/effective_go.html)
- [RFC 6238 (TOTP)](https://tools.ietf.org/html/rfc6238)
- [TLS 1.3](https://tools.ietf.org/html/rfc8446)
- [HoneyBee Protocol](../../bee_docs/src/protocol.md)

