// Package constants defines application-wide constants and default values
// used throughout the HoneyBee Node application. Centralizing constants
// improves maintainability and reduces magic numbers in the codebase.
package constants

import "time"

// Application metadata
const (
	// AppName is the application name
	AppName = "HoneyBee Node"
	// AppVersion is the current version
	AppVersion = "1.0.0"
	// AppDescription is a brief description of the application
	AppDescription = "Distributed honeypot node for the HoneyBee platform"
)

// Protocol constants
const (
	// ProtocolVersion is the current protocol version (must match honeybee_core)
	ProtocolVersion uint64 = 2
	// MaxMessageSize is the maximum size of a protocol message in bytes (10MB)
	MaxMessageSize = 10 * 1024 * 1024
	// MessageBufferSize is the size of the message channel buffer
	MessageBufferSize = 100
)

// Network constants
const (
	// DefaultServerPort is the default port for the HoneyBee Core server
	DefaultServerPort = 9001
	// DefaultEventListenerPort is the default port for receiving honeypot events
	DefaultEventListenerPort = 9100
	// ConnectionTimeout is the timeout for establishing connections
	ConnectionTimeout = 30 * time.Second
	// ReconnectDelay is the delay between reconnection attempts
	ReconnectDelay = 5 * time.Second
	// HeartbeatInterval is the interval between heartbeat messages
	HeartbeatInterval = 30 * time.Second
	// ReadTimeout is the timeout for reading from network connections
	ReadTimeout = 60 * time.Second
	// WriteTimeout is the timeout for writing to network connections
	WriteTimeout = 30 * time.Second
)

// TLS constants
const (
	// TLSMinVersion is the minimum TLS version (TLS 1.3)
	TLSMinVersion = "1.3"
	// DefaultServerName is the default server name for TLS verification
	DefaultServerName = "honeybee-core"
)

// TOTP constants
const (
	// TOTPSecretFile is the filename for storing TOTP secrets
	TOTPSecretFile = ".honeybee_totp_secret"
	// TOTPIssuer is the issuer name shown in authenticator apps
	TOTPIssuer = "HoneyBee"
	// TOTPSecretLength is the length of the TOTP secret in bytes
	TOTPSecretLength = 20
	// TOTPValidityWindow is the number of time steps to check for valid codes
	TOTPValidityWindow = 1
)

// Honeypot constants
const (
	// DefaultHoneypotBaseDir is the default directory for honeypot installations
	DefaultHoneypotBaseDir = "~/.honeybee/honeypots"
	// DefaultSSHPort is the default SSH port for honeypots
	DefaultSSHPort = 2222
	// DefaultTelnetPort is the default Telnet port for honeypots
	DefaultTelnetPort = 2223
	// HoneypotEventBufferSize is the size of the honeypot event channel buffer
	HoneypotEventBufferSize = 1000
	// PotStoreURL is the default URL for the HoneyBee potstore repository
	PotStoreURL = "https://github.com/H0neyBe/honeybee_potstore"
	// PotStoreBranch is the default branch for the potstore
	PotStoreBranch = "main"
	// PotStoreTempDir is the temporary directory name for cloning potstore
	PotStoreTempDir = ".potstore-temp"
	// HoneypotSetupTimeout is the maximum time allowed for honeypot setup
	HoneypotSetupTimeout = 5 * time.Minute
	// HoneypotStartTimeout is the maximum time to wait for honeypot startup
	HoneypotStartTimeout = 30 * time.Second
	// HoneypotStopTimeout is the maximum time to wait for honeypot shutdown
	HoneypotStopTimeout = 15 * time.Second
)

// Python/Virtual environment constants
const (
	// PythonCommand is the command to run Python
	PythonCommand = "python"
	// VenvDirName is the directory name for Python virtual environments
	VenvDirName = "cowrie-env"
	// RequirementsFile is the name of the Python requirements file
	RequirementsFile = "requirements.txt"
)

// Platform-specific constants (Windows)
const (
	// WindowsVenvScriptsDir is the scripts directory in Windows venv
	WindowsVenvScriptsDir = "Scripts"
	// WindowsPythonExe is the Python executable name on Windows
	WindowsPythonExe = "python.exe"
	// WindowsTwistdExe is the Twistd executable name on Windows
	WindowsTwistdExe = "twistd.exe"
)

// Platform-specific constants (Unix/Linux)
const (
	// UnixVenvBinDir is the bin directory in Unix venv
	UnixVenvBinDir = "bin"
	// UnixPythonExe is the Python executable name on Unix
	UnixPythonExe = "python"
	// UnixTwistdExe is the Twistd executable name on Unix
	UnixTwistdExe = "twistd"
)

// Configuration constants
const (
	// DefaultConfigDir is the default configuration directory
	DefaultConfigDir = "~/.config/honeybee"
	// DefaultLogLevel is the default logging level
	DefaultLogLevel = "info"
	// DefaultLogFormat is the default log format
	DefaultLogFormat = "text"
	// ConfigFilePermissions is the file permissions for configuration files
	ConfigFilePermissions = 0600
	// DirPermissions is the default permissions for created directories
	DirPermissions = 0755
	// SecretDirPermissions is the permissions for directories storing secrets
	SecretDirPermissions = 0700
)

// Logging constants
const (
	// LogFieldNodeID is the field name for node ID in logs
	LogFieldNodeID = "node_id"
	// LogFieldNodeName is the field name for node name in logs
	LogFieldNodeName = "node_name"
	// LogFieldNodeType is the field name for node type in logs
	LogFieldNodeType = "node_type"
	// LogFieldHoneypotID is the field name for honeypot ID in logs
	LogFieldHoneypotID = "honeypot_id"
	// LogFieldHoneypotType is the field name for honeypot type in logs
	LogFieldHoneypotType = "honeypot_type"
	// LogFieldEventType is the field name for event type in logs
	LogFieldEventType = "event_type"
	// LogFieldError is the field name for errors in logs
	LogFieldError = "error"
	// LogTimestampFormat is the format for timestamps in logs
	LogTimestampFormat = "2006-01-02T15:04:05.000Z07:00"
)

// File operation constants
const (
	// MaxRetries is the maximum number of retries for operations
	MaxRetries = 3
	// RetryDelay is the delay between retries
	RetryDelay = 1 * time.Second
	// FileCopyBufferSize is the buffer size for file copy operations
	FileCopyBufferSize = 64 * 1024
)

// Status update intervals
const (
	// StatusUpdateInterval is how often to send status updates
	StatusUpdateInterval = 30 * time.Second
	// EventProcessingInterval is how often to process queued events
	EventProcessingInterval = 100 * time.Millisecond
)

// Supported honeypot types
var (
	// SupportedHoneypotTypes lists all honeypot types this node can run
	SupportedHoneypotTypes = []string{
		"cowrie",
		// Future: "dionaea", "kippo", etc.
	}
)

// Environment variables
const (
	// EnvCowrieStdout is the environment variable to enable Cowrie stdout logging
	EnvCowrieStdout = "COWRIE_STDOUT"
	// EnvPythonPath is the environment variable for Python module search path
	EnvPythonPath = "PYTHONPATH"
)

