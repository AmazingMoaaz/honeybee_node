# Honey Bee Node

[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Protocol](https://img.shields.io/badge/Protocol-v2-green.svg)](https://github.com/yourusername/honeybee/blob/main/bee_docs/src/protocol.md)

A **production-ready**, secure Go implementation of a HoneyBee node with TLS 1.3 encryption and TOTP authentication.

## Features

🔐 **TLS 1.3 Encryption** • 🔑 **TOTP Authentication** • 🔄 **Auto Reconnection** • 📊 **Structured Logging** • 🚀 **Production Ready**

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
├── internal/              # Core implementation
│   ├── auth/             # TLS + TOTP authentication
│   ├── client/           # Node client
│   ├── config/           # Configuration
│   ├── logger/           # Logging
│   └── protocol/         # Protocol v2
├── configs/              # Configuration files
├── Makefile              # Build automation
└── README.md             # This file
```

## Basic Configuration

```yaml
node:
  name: "my-node"
  type: "Agent"  # or "Full"

server:
  address: "manager.example.com:9001"

tls:
  enabled: true  # ⚠️ Always true in production
  ca_file: "/path/to/ca.crt"

auth:
  totp_enabled: true  # ⚠️ Always true in production

log:
  level: "info"
  format: "json"
```

**See [Configuration Guide](../bee_docs/src/node/configuration.md) for all options.**

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

## Requirements

- **Runtime**: None (static binary)
- **Build**: Go 1.21+
- **OS**: Linux, Windows, macOS

## Protocol

Implements **HoneyBee Protocol v2**:

**Node → Manager:**
- NodeRegistration
- NodeStatusUpdate
- NodeEvent
- NodeDrop

**Manager → Node:**
- RegistrationAck
- NodeCommand

**See [Protocol Specification](../bee_docs/src/protocol.md) for details.**

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
