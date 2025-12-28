# HoneyBee Node

[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Protocol](https://img.shields.io/badge/Protocol-v2-green.svg)](https://github.com/H0neyBe/honeybee_node)
[![Status](https://img.shields.io/badge/Status-Beta-orange)](https://github.com/H0neyBe/honeybee_node)

A Go implementation of a HoneyBee node that connects to the HoneyBee Core manager, manages honeypot deployments, and forwards attack data in real-time. Features TLS 1.3 encryption, TOTP authentication, automatic honeypot installation, and comprehensive event forwarding. Currently in **Beta** - active development and testing.

## Table of Contents

- [Features](#features)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Node Types](#node-types)
- [Command Line Options](#command-line-options)
- [Supported Honeypots](#supported-honeypots)
- [Honeypot Management](#honeypot-management)
- [Project Structure](#project-structure)
- [Makefile Commands](#makefile-commands)
- [Deployment](#deployment)
- [Security](#security)
- [Protocol](#protocol)
- [Requirements](#requirements)
- [Troubleshooting](#troubleshooting)
- [Development](#development)
- [Contributing](#contributing)
- [License](#license)
- [Related Projects](#related-projects)
- [Support](#support)

## Features

🔐 **TLS 1.3 Encryption** - Secure communication with the manager  
🔑 **TOTP Authentication** - Time-based one-time password support  
🍯 **Honeypot Management** - Install, start, stop, and monitor honeypots  
🔄 **Auto Reconnection** - Automatic reconnection with exponential backoff  
📊 **Structured Logging** - JSON and text logging with logrus  
🌐 **Multi-Platform** - Linux, Windows, and macOS support  
🚀 **Beta Release** - Graceful shutdown, error recovery, and monitoring (actively tested)  

## Quick Start

### 1. Build the Binary

```bash
# Build for current platform
make build

# Or build for specific platforms
make build-linux
make build-windows
make build-darwin
make build-all  # Build for all platforms
```

### 2. Generate Configuration

```bash
# Generate default configuration file
./build/honeybee-node -gen-config

# Or use the Makefile
make gen-config
```

This creates `configs/config.yaml` with sensible defaults.

### 3. Configure the Node

Edit `configs/config.yaml` and set at minimum:

```yaml
node:
  name: "my-node"  # Unique node identifier
  type: "Full"     # "Full" for honeypot management, "Agent" for monitoring only

server:
  address: "manager.example.com:9001"  # HoneyBee Core manager address
```

### 4. Run the Node

```bash
# Run with default config
./build/honeybee-node

# Or specify config path
./build/honeybee-node -config configs/config.yaml

# Enable debug logging
./build/honeybee-node -config configs/config.yaml -debug

# Validate configuration without running
./build/honeybee-node -config configs/config.yaml -validate
```

### 5. Verify Connection

The node will:
- Connect to the HoneyBee Core manager
- Register with TOTP authentication (if enabled)
- Start sending heartbeat messages
- Listen for honeypot management commands

Check the logs to confirm successful connection.

## Configuration

### Basic Configuration

```yaml
node:
  name: "honeybee-node-01"
  type: "Full"  # "Full" or "Agent"
  address: "0.0.0.0"
  port: 8080

server:
  address: "10.10.1.3:9001"
  heartbeat_interval: 30  # seconds
  reconnect_delay: 5      # seconds
  connection_timeout: 10   # seconds

tls:
  enabled: true
  insecure_skip_verify: false
  server_name: "honeybee-manager"
  # cert_file: "certs/client.crt"  # Optional: client certificate
  # key_file: "certs/client.key"   # Optional: client key
  # ca_file: "certs/ca.crt"        # Optional: CA certificate

auth:
  totp_enabled: true
  # totp_secret_dir: "~/.config/honeybee"  # Optional: custom secret directory

log:
  level: "info"   # debug, info, warn, error
  format: "text"  # text or json
  # file: "/var/log/honeybee/node.log"  # Optional: log to file

honeypot:
  enabled: true
  base_dir: "~/.honeybee/honeypots"
  default_ssh_port: 2222
  default_telnet_port: 2223
```

### Configuration Options

| Section | Option | Description | Default |
|---------|--------|-------------|---------|
| `node` | `name` | Unique node identifier | Hostname |
| `node` | `type` | Node type: "Full" or "Agent" (see [Node Types](#node-types)) | "Full" |
| `server` | `address` | Manager server address | "127.0.0.1:9001" |
| `server` | `heartbeat_interval` | Heartbeat interval (seconds) | 30 |
| `tls` | `enabled` | Enable TLS encryption | true |
| `tls` | `insecure_skip_verify` | Skip certificate verification | false |
| `auth` | `totp_enabled` | Enable TOTP authentication | true |
| `log` | `level` | Logging level | "info" |
| `log` | `format` | Log format: "text" or "json" | "text" |
| `honeypot` | `enabled` | Enable honeypot management | true |
| `honeypot` | `base_dir` | Honeypot installation directory | "~/.honeybee/honeypots" |

See `configs/config.yaml` for a complete example with comments.

## Node Types

The node type indicates the intended capability level of the node to the HoneyBee Core manager:

### Full Node (`type: "Full"`)

A **Full** node is designed for complete honeypot management capabilities:

- ✅ **Honeypot Installation** - Can install honeypots from Potstore or Git repositories
- ✅ **Honeypot Management** - Can start, stop, restart, and monitor honeypots
- ✅ **Event Forwarding** - Forwards all honeypot events to the manager
- ✅ **Status Reporting** - Reports honeypot status and health metrics

**Use Case**: Production deployments where you need full honeypot management capabilities.

**Configuration**:
```yaml
node:
  type: "Full"

honeypot:
  enabled: true  # Required for Full nodes
```

### Agent Node (`type: "Agent"`)

An **Agent** node is designed as a lightweight monitoring probe:

- ✅ **Status Reporting** - Reports node health and status
- ✅ **Event Reception** - Can receive events from external sources
- ❌ **No Honeypot Management** - Cannot install or manage honeypots
- ❌ **No Event Forwarding** - Does not forward honeypot events

**Use Case**: Lightweight monitoring nodes, network probes, or nodes that only report status without running honeypots.

**Configuration**:
```yaml
node:
  type: "Agent"

honeypot:
  enabled: false  # Typically disabled for Agent nodes
```

### Important Notes

- **Node type is informational** - It's sent to the manager during registration to indicate capabilities
- **Honeypot management is controlled by `honeypot.enabled`** - The actual ability to manage honeypots depends on this setting, not just the node type
- **Manager uses node type** - The HoneyBee Core manager may use the node type to determine which commands to send to which nodes
- **Default is "Full"** - New nodes default to "Full" type for maximum capabilities

## Command Line Options

```bash
honeybee-node [flags]

Flags:
  -config string
        Path to configuration file (default "configs/config.yaml")
  -version
        Show version information and exit
  -gen-config
        Generate default configuration file and exit
  -validate
        Validate configuration and exit
  -debug
        Enable debug logging (overrides config file)
```

## Supported Honeypots

The node supports installing and managing honeypots from the [HoneyBee Potstore](https://github.com/H0neyBe/honeybee_potstore):

- **Cowrie** - SSH and Telnet honeypot (Python/Twisted)
- **HonnyPotter** - WordPress login honeypot (PHP)
- **Dionaea** - Multi-protocol honeypot
- **Heralding** - Credential honeypot
- **Elasticpot** - Elasticsearch honeypot
- **Mailoney** - SMTP honeypot

Honeypots are automatically installed from the Potstore repository, configured with HoneyBee event forwarding, and managed by the node.

## Honeypot Management

Once connected to the manager, honeypots can be installed and managed remotely:

### Installation Flow

1. **Manager sends InstallPot command** - Specifies honeypot type, ID, and configuration
2. **Node clones repository** - Downloads honeypot from Potstore or custom Git URL
3. **Node sets up environment** - Creates virtual environments, installs dependencies
4. **Node configures integration** - Sets up event forwarding to HoneyBee Core
5. **Node reports status** - Sends installation progress and completion status

### Event Forwarding

All honeypot events (login attempts, commands, attacks) are automatically forwarded to the HoneyBee Core manager via:
- **TCP Socket** - Events sent to `localhost:9100` (configurable via `HONEYBEE_EVENT_PORT`)
- **JSON Format** - Structured event data with metadata
- **Real-time** - Events forwarded immediately as they occur

#### Event Format

Events are sent as JSON messages with the following structure:

```json
{
  "node_id": 12345,
  "pot_id": "cowrie-01",
  "pot_type": "cowrie",
  "event_type": "login",
  "timestamp": "2024-01-15T10:30:00Z",
  "data": {
    "username": "admin",
    "password": "password123",
    "ip": "192.168.1.100",
    "session": "abc123"
  }
}
```

## Project Structure

```
honeybee_node/
├── cmd/node/              # Application entry point
│   ├── main.go           # CLI with flags and initialization
│   └── configs/          # Example configurations
├── internal/             # Core implementation
│   ├── auth/             # TLS and TOTP authentication
│   │   ├── tls.go        # TLS configuration and validation
│   │   └── totp.go       # TOTP generation and validation
│   ├── client/           # Node client and connection manager
│   │   └── client.go     # Connection handling, reconnection logic
│   ├── config/           # Configuration management
│   │   └── config.go     # YAML loading, validation, defaults
│   ├── constants/        # Application constants
│   │   └── constants.go  # Defaults, timeouts, paths
│   ├── errors/           # Structured error handling
│   │   └── errors.go     # Error categories and codes
│   ├── honeypot/         # Honeypot lifecycle management
│   │   └── manager.go    # Install, start, stop, monitor honeypots
│   ├── logger/           # Structured logging
│   │   └── logger.go     # Logrus wrapper with structured fields
│   └── protocol/         # Protocol v2 implementation
│       └── protocol.go    # Message types and validation
├── configs/              # Configuration files
│   └── config.yaml       # Default configuration template
├── Makefile              # Build automation
├── Dockerfile            # Docker image definition
├── go.mod                # Go module dependencies
├── SECURITY.md           # Security policy and best practices
└── README.md             # This file
```

## Makefile Commands

```bash
make build          # Build binary for current platform
make build-linux    # Build for Linux (amd64)
make build-windows  # Build for Windows (amd64)
make build-darwin   # Build for macOS (amd64 + arm64)
make build-all      # Build for all platforms
make run            # Build and run
make dev            # Run in development mode
make test           # Run tests
make test-coverage  # Run tests with coverage report
make clean          # Clean build artifacts
make deps           # Download and tidy dependencies
make fmt            # Format code
make vet            # Run go vet
make lint           # Run golangci-lint (if installed)
make gen-config     # Generate default configuration
make docker-build   # Build Docker image
make help           # Show all available commands
```

## Deployment

### Systemd Service (Linux)

```bash
# Copy binary
sudo cp build/honeybee-node /usr/local/bin/
sudo chmod +x /usr/local/bin/honeybee-node

# Create systemd service file
sudo tee /etc/systemd/system/honeybee-node.service > /dev/null <<EOF
[Unit]
Description=HoneyBee Node
After=network.target

[Service]
Type=simple
User=honeybee
ExecStart=/usr/local/bin/honeybee-node -config /etc/honeybee/config.yaml
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# Create user and directories
sudo useradd -r -s /bin/false honeybee
sudo mkdir -p /etc/honeybee /var/log/honeybee
sudo chown honeybee:honeybee /etc/honeybee /var/log/honeybee

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable honeybee-node
sudo systemctl start honeybee-node
sudo systemctl status honeybee-node
```

### Docker

```bash
# Build image
docker build -t honeybee-node:latest .

# Run container
docker run -d \
  --name honeybee-node \
  -v $(pwd)/configs:/app/configs:ro \
  -v honeybee-honeypots:/app/honeypots \
  honeybee-node:latest \
  -config configs/config.yaml
```

### Windows Service

Use [NSSM](https://nssm.cc/) or similar service manager:

```powershell
# Install as service
nssm install HoneyBeeNode "C:\Program Files\HoneyBee\honeybee-node.exe"
nssm set HoneyBeeNode AppParameters "-config C:\Program Files\HoneyBee\config.yaml"
nssm set HoneyBeeNode AppDirectory "C:\Program Files\HoneyBee"
nssm start HoneyBeeNode
```

## Security

### Production Checklist

- ✅ **TLS enabled** - Always use TLS in production
- ✅ **Certificate verification** - Never skip verification
- ✅ **TOTP enabled** - Enable TOTP authentication
- ✅ **Non-root user** - Run as dedicated user
- ✅ **Firewall configured** - Restrict network access
- ✅ **Secrets secured** - Proper file permissions (0600)
- ✅ **Logs monitored** - Monitor for anomalies
- ✅ **Regular updates** - Keep dependencies updated

### TLS Setup

```yaml
tls:
  enabled: true
  insecure_skip_verify: false
  server_name: "honeybee-manager"
  ca_file: "/etc/honeybee/certs/ca.crt"  # CA certificate for verification
```

### TOTP Setup

1. **Enable TOTP** in configuration:
   ```yaml
   auth:
     totp_enabled: true
   ```

2. **Generate QR code** on first run (check logs)

3. **Scan with authenticator app** (Google Authenticator, Authy, etc.)

4. **Use code during registration** when connecting to manager

See [SECURITY.md](./SECURITY.md) for detailed security guidelines.

## Protocol

Implements **HoneyBee Protocol v2** for communication with HoneyBee Core:

### Node → Manager Messages

- `NodeRegistration` - Initial handshake with TOTP code
- `NodeStatusUpdate` - Periodic health and status reports
- `NodeEvent` - Node lifecycle events (Started, Stopped, Error)
- `PotStatusUpdate` - Honeypot state changes (Installing, Running, Stopped, Failed)
- `PotEvent` - Attack data from honeypots (login attempts, commands, sessions)

### Manager → Node Commands

- `RegistrationAck` - Registration confirmation
- `NodeCommand` - General control commands
- `InstallPot` - Install honeypot from Potstore or Git repository
- `StartPot` - Start a honeypot instance
- `StopPot` - Stop a honeypot instance
- `NodeDrop` - Request node disconnection

All messages are JSON-encoded and sent over TCP with optional TLS encryption.

## Requirements

- **Runtime**: Static binary (no dependencies)
- **Build**: Go 1.21 or later
- **OS**: Linux, Windows, macOS
- **For Honeypots**: 
  - Python 3.7+ (for Python-based honeypots)
  - PHP 7.4+ (for PHP-based honeypots like HonnyPotter)
  - Git (for cloning honeypot repositories)

## Troubleshooting

### Node Won't Connect

1. **Check manager address** - Verify `server.address` in config
2. **Check network** - Ensure manager is reachable
3. **Check TLS** - Verify certificates if TLS enabled
4. **Check TOTP** - Ensure TOTP code is valid
5. **Check logs** - Enable debug logging: `-debug` flag

### Honeypot Installation Fails

1. **Check Python/PHP** - Ensure required runtime is installed
   ```bash
   python3 --version  # Should be 3.7+
   php --version      # Should be 7.4+ (for PHP honeypots)
   ```

2. **Check Git** - Ensure Git is available
   ```bash
   git --version
   ```

3. **Check disk space** - Ensure sufficient space for installations
   ```bash
   df -h ~/.honeybee/honeypots
   ```

4. **Check permissions** - Ensure write access to `honeypot.base_dir`
   ```bash
   ls -la ~/.honeybee/honeypots
   ```

5. **Check logs** - Review installation logs for errors
   ```bash
   ./build/honeybee-node -config configs/config.yaml -debug
   ```

### Events Not Forwarding

1. **Check event listener** - Verify port 9100 is available
   ```bash
   netstat -tuln | grep 9100  # Linux
   netstat -an | grep 9100    # macOS/Windows
   ```

2. **Check honeypot config** - Ensure HoneyBee forwarder is configured
   - For Cowrie: Check `honeybee.py` output plugin is enabled
   - For HonnyPotter: Check `honeybee-forwarder.php` is included

3. **Check network** - Verify honeypot can reach localhost:9100
   ```bash
   telnet localhost 9100  # Should connect
   ```

4. **Check environment variables** - Verify `HONEYBEE_EVENT_PORT` is set correctly
   ```bash
   echo $HONEYBEE_EVENT_PORT  # Should be 9100
   ```

5. **Check logs** - Enable debug logging to see event flow
   ```bash
   ./build/honeybee-node -config configs/config.yaml -debug
   ```

## Development

### Building from Source

```bash
# Clone repository
git clone https://github.com/H0neyBe/honeybee_node.git
cd honeybee_node

# Download dependencies
go mod download

# Build
make build

# Run tests
make test
```

### Code Structure

- **Package-based architecture** - Clear separation of concerns
- **Structured errors** - Custom error types with categories
- **Comprehensive logging** - Structured logging with contextual fields
- **Input validation** - All inputs validated at boundaries
- **Thread-safe** - Safe concurrent access where needed

## Contributing

Contributions are welcome! We appreciate your help in making HoneyBee Node better.

### How to Contribute

1. **Fork the repository** - Create your own fork of [honeybee_node](https://github.com/H0neyBe/honeybee_node)
2. **Create a feature branch** - Use a descriptive branch name (e.g., `feature/add-new-honeypot-support`)
3. **Make your changes** - Follow the existing code style and add tests
4. **Test your changes** - Run `make test` to ensure everything works
5. **Submit a pull request** - Provide a clear description of your changes

### Development Guidelines

- Follow Go best practices and conventions
- Add tests for new features
- Update documentation as needed
- Ensure all tests pass before submitting
- Use meaningful commit messages

### Areas for Contribution

- 🐛 Bug fixes
- ✨ New features
- 📚 Documentation improvements
- 🧪 Test coverage
- 🎨 Code quality improvements
- 🌐 Additional honeypot support

## License

See [LICENSE](./LICENSE) file for details.

## Related Projects

- **[HoneyBee Core](https://github.com/H0neyBe/honeybee_core)** - Central manager (Rust)
- **[HoneyBee Potstore](https://github.com/H0neyBe/honeybee_potstore)** - Honeypot repository and registry

## Support

- 📖 **Documentation**: Check the configuration file comments for detailed options
- 🐛 **Issues**: [Report bugs or request features](https://github.com/H0neyBe/honeybee_node/issues)
- 💬 **Discussions**: [Join discussions](https://github.com/H0neyBe/honeybee_node/discussions) for questions and help
- 📚 **Documentation Site**: [HoneyBee Documentation](https://h0neybe.github.io/bee_docs/)
- 🔗 **Repository**: [HoneyBee Node on GitHub](https://github.com/H0neyBe/honeybee_node)

---

**Status**: 🧪 Beta | **Version**: 1.0.0 | **Protocol**: v2

For more information, visit the [HoneyBee Documentation](https://h0neybe.github.io/bee_docs/).
