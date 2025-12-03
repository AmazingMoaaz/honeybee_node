# Honey Bee Node

[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Protocol](https://img.shields.io/badge/Protocol-v2-green.svg)](https://github.com/yourusername/honeybee/blob/main/bee_docs/src/protocol.md)

A **production-ready**, secure Go implementation of a HoneyBee node with TLS 1.3 encryption, TOTP authentication, and distributed honeypot management. Features professional code structure, comprehensive validation, structured error handling, and extensive documentation.

## Features

🔐 **TLS 1.3 Encryption** • 🔑 **TOTP Authentication** • 🍯 **Honeypot Management** • 🔄 **Auto Reconnection** • 📊 **Structured Logging** • ✨ **Professional Code** • 🚀 **Production Ready**

## Quick Start

```bash
# 1. Build
make build

# 2. Generate config
./build/honeybee-node -gen-config

# 3. Edit config (set your manager address)
vim configs/config.yaml

# 4. Run
./build/honeybee-node -config configs/config.yaml
```

**See [Quick Start Guide](../bee_docs/src/node/installation.md) for detailed instructions.**

## Documentation

📖 **Complete documentation** is available at **[bee_docs/](../bee_docs/)**

| Document | Description |
|----------|-------------|
| [Overview](../bee_docs/src/node/overview.md) | What is HoneyBee Node? |
| [Installation](../bee_docs/src/node/installation.md) | Installation & quick start |
| [Configuration](../bee_docs/src/node/configuration.md) | Complete configuration reference |
| [Security Setup](../bee_docs/src/node/security.md) | Security best practices |
| [TLS Setup](../bee_docs/src/node/tls.md) | TLS encryption configuration |
| [TOTP Setup](../bee_docs/src/node/totp.md) | TOTP authentication setup |
| [Deployment](../bee_docs/src/node/deployment.md) | Production deployment guide |
| [Architecture](../bee_docs/src/node/architecture.md) | Technical architecture |
| [Examples](../bee_docs/src/node/examples.md) | Usage examples |
| [Troubleshooting](../bee_docs/src/node/troubleshooting.md) | Common issues & solutions |

## Project Structure

```
honeybee_node/
├── cmd/node/              # Application entry point
│   └── main.go           # CLI with enhanced flags
├── internal/              # Core implementation
│   ├── auth/             # TLS 1.3 + TOTP authentication
│   │   ├── tls.go        # TLS configuration & validation
│   │   └── totp.go       # TOTP generation & validation
│   ├── client/           # Node client & connection manager
│   ├── config/           # Configuration management & validation
│   ├── constants/        # Application constants & defaults
│   ├── errors/           # Structured error handling
│   ├── honeypot/         # Honeypot lifecycle management
│   │   └── manager.go    # Install, start, stop, monitor
│   ├── logger/           # Structured logging (logrus)
│   └── protocol/         # Protocol v2 with validation
├── configs/              # Configuration files
├── docs/                 # Documentation
├── Makefile              # Build automation
├── ARCHITECTURE.md       # Technical architecture guide
├── ENHANCEMENTS.md       # Code enhancements documentation
└── README.md             # This file
```

## Basic Configuration

```yaml
node:
  name: "my-node"
  type: "Full"  # "Full" = honeypot support, "Agent" = lightweight

server:
  address: "manager.example.com:9001"
  heartbeat_interval: 30
  reconnect_delay: 5

tls:
  enabled: true  # ⚠️ Always true in production
  ca_file: "~/.honeybee/certs/ca.crt"
  insecure_skip_verify: false

auth:
  totp_enabled: true  # ⚠️ Always true in production

honeypot:
  enabled: true
  base_dir: "~/.honeybee/honeypots"
  default_ssh_port: 2222
  default_telnet_port: 2223

log:
  level: "info"
  format: "json"
```

**See [ARCHITECTURE.md](./ARCHITECTURE.md) and [Configuration Guide](../bee_docs/src/node/configuration.md) for all options.**

## Makefile Commands

```bash
make build         # Build binary
make run           # Build and run
make dev           # Development mode
make test          # Run tests
make clean         # Clean build artifacts
make docker-build  # Build Docker image
```

**See `make help` for all commands.**

## Security

⚠️ **Production Deployment Checklist:**

- ✅ TLS encryption enabled
- ✅ Valid certificates installed
- ✅ Certificate verification enabled
- ✅ TOTP authentication enabled
- ✅ Running as non-root user
- ✅ Firewall configured
- ✅ Secrets properly secured
- ✅ Logs monitored

**See [Security Guide](../bee_docs/src/node/security.md) for complete setup.**

## Deployment

### Systemd Service

```bash
sudo cp build/honeybee-node /usr/local/bin/
sudo cp systemd/honeybee-node.service /etc/systemd/system/
sudo systemctl enable --now honeybee-node
```

**See [Deployment Guide](../bee_docs/src/node/deployment.md) for all options.**

### Docker

```bash
docker build -t honeybee-node:latest .
docker run -d --name honeybee-node honeybee-node:latest
```

### Kubernetes

```bash
kubectl apply -f k8s/
```

## Code Quality & Best Practices

This codebase follows professional Go development practices:

✅ **Comprehensive Documentation** - Every package and function documented  
✅ **Structured Error Handling** - Custom error types with categories and codes  
✅ **Input Validation** - All inputs validated at package boundaries  
✅ **Constants Centralization** - No magic numbers, all in `constants` package  
✅ **Secure Defaults** - Secure file permissions, TLS 1.3, strong ciphers  
✅ **Thread Safety** - Safe concurrent access where needed  
✅ **Professional Structure** - Clear separation of concerns  
✅ **Extensive Logging** - Structured logging with contextual fields  
✅ **Production Ready** - Error recovery, reconnection, graceful shutdown  

**See [ENHANCEMENTS.md](./ENHANCEMENTS.md) for detailed documentation of code improvements.**

### New Packages
- `internal/errors` - Structured error handling with categories
- `internal/constants` - Application-wide constants and defaults
- Enhanced packages: `protocol`, `logger`, `auth`, `config`

## Requirements

- **Runtime**: None (static binary)
- **Build**: Go 1.21+
- **OS**: Linux, Windows, macOS
- **For Honeypots**: Python 3.7+ (automatically managed in virtual environments)

## Protocol

Implements **HoneyBee Protocol v2** with comprehensive validation:

**Node → Manager:**
- `NodeRegistration` - Initial handshake with TOTP
- `NodeStatusUpdate` - Periodic health reports
- `NodeEvent` - General events (Started, Stopped, Error)
- `HoneypotStatusUpdate` - Honeypot state changes
- `HoneypotEvent` - Attack data (SSH/Telnet attempts, commands)

**Manager → Node:**
- `RegistrationAck` - Registration confirmation
- `NodeCommand` - Control commands
- `InstallHoneypotCmd` - Install honeypot from GitHub
- `StartHoneypotCmd` - Start honeypot instance
- `StopHoneypotCmd` - Stop honeypot instance

**See [ARCHITECTURE.md](./ARCHITECTURE.md) and [Protocol Specification](../bee_docs/src/protocol.md) for details.**

## Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

See [LICENSE](LICENSE).

## Related Projects

- [HoneyBee Core](../honeybee_core) - Central manager (Rust)
- [HoneyBee Docs](../bee_docs) - Complete documentation

## Support

- 📖 [Documentation](../bee_docs/)
- 🐛 [Issues](https://github.com/yourusername/honeybee/issues)
- 💬 [Discussions](https://github.com/yourusername/honeybee/discussions)

---

**Status**: ✅ Production Ready | **Version**: 1.0.0 | **Protocol**: v2

For complete documentation, visit **[bee_docs/](../bee_docs/)**
