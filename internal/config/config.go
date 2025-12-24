// Package config provides configuration management for the HoneyBee Node.
// It supports loading configuration from YAML files, validation, and
// sensible defaults for all settings.
//
// Configuration can be loaded from a file or generated with defaults:
//
//	cfg, err := config.LoadConfig("config.yaml")
//	cfg := config.DefaultConfig()
package config

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/honeybee/node/internal/constants"
	"github.com/honeybee/node/internal/errors"
	"gopkg.in/yaml.v3"
)

// Config represents the complete node configuration with all subsystems
type Config struct {
	Node     NodeConfig     `yaml:"node"`
	Server   ServerConfig   `yaml:"server"`
	TLS      TLSConfig      `yaml:"tls"`
	Auth     AuthConfig     `yaml:"auth"`
	Log      LogConfig      `yaml:"log"`
	Honeypot HoneypotConfig `yaml:"honeypot"`
}

// NodeConfig defines node-specific settings
type NodeConfig struct {
	Name    string `yaml:"name"`
	Type    string `yaml:"type"`    // "Full" or "Agent"
	Address string `yaml:"address"` // Address to report to manager
	Port    uint16 `yaml:"port"`    // Port to report to manager
}

// ServerConfig defines connection settings
type ServerConfig struct {
	Address           string `yaml:"address"`
	HeartbeatInterval int    `yaml:"heartbeat_interval"` // seconds
	ReconnectDelay    int    `yaml:"reconnect_delay"`    // seconds
	ConnectionTimeout int    `yaml:"connection_timeout"` // seconds
}

// TLSConfig defines TLS settings
type TLSConfig struct {
	Enabled            bool   `yaml:"enabled"`
	CertFile           string `yaml:"cert_file,omitempty"`
	KeyFile            string `yaml:"key_file,omitempty"`
	CAFile             string `yaml:"ca_file,omitempty"`
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
	ServerName         string `yaml:"server_name,omitempty"`
}

// AuthConfig defines authentication settings
type AuthConfig struct {
	TOTPEnabled   bool   `yaml:"totp_enabled"`
	TOTPSecretDir string `yaml:"totp_secret_dir,omitempty"`
}

// LogConfig defines logging settings
type LogConfig struct {
	Level  string `yaml:"level"`  // debug, info, warn, error
	Format string `yaml:"format"` // text, json
	File   string `yaml:"file,omitempty"`
}

// HoneypotConfig defines honeypot management settings
type HoneypotConfig struct {
	Enabled    bool   `yaml:"enabled"`             // Enable honeypot management
	BaseDir    string `yaml:"base_dir,omitempty"`  // Base directory for honeypot installations
	DefaultSSH uint16 `yaml:"default_ssh_port"`    // Default SSH honeypot port
	DefaultTel uint16 `yaml:"default_telnet_port"` // Default Telnet honeypot port
}

// LoadConfig loads configuration from a YAML file.
// It automatically expands ~ in paths and validates the configuration.
// Returns an error if the file cannot be read, parsed, or is invalid.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCategoryConfig, "CONFIG_READ_FAILED",
			fmt.Sprintf("Failed to read config file: %s", path))
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, errors.Wrap(err, errors.ErrCategoryConfig, "CONFIG_PARSE_FAILED",
			fmt.Sprintf("Failed to parse config file: %s", path))
	}

	// Expand ~ in paths to user home directory
	cfg.ExpandPaths()

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return nil, errors.Wrap(err, errors.ErrCategoryConfig, "CONFIG_INVALID",
			"Configuration validation failed")
	}

	return &cfg, nil
}

// ExpandPaths expands ~ to user home directory in all path fields
func (c *Config) ExpandPaths() {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return
	}

	// Expand honeypot base dir
	if strings.HasPrefix(c.Honeypot.BaseDir, "~") {
		c.Honeypot.BaseDir = filepath.Join(homeDir, c.Honeypot.BaseDir[1:])
	}

	// Expand TLS paths
	if strings.HasPrefix(c.TLS.CertFile, "~") {
		c.TLS.CertFile = filepath.Join(homeDir, c.TLS.CertFile[1:])
	}
	if strings.HasPrefix(c.TLS.KeyFile, "~") {
		c.TLS.KeyFile = filepath.Join(homeDir, c.TLS.KeyFile[1:])
	}
	if strings.HasPrefix(c.TLS.CAFile, "~") {
		c.TLS.CAFile = filepath.Join(homeDir, c.TLS.CAFile[1:])
	}

	// Expand log file path
	if strings.HasPrefix(c.Log.File, "~") {
		c.Log.File = filepath.Join(homeDir, c.Log.File[1:])
	}

	// Expand TOTP secret dir
	if strings.HasPrefix(c.Auth.TOTPSecretDir, "~") {
		c.Auth.TOTPSecretDir = filepath.Join(homeDir, c.Auth.TOTPSecretDir[1:])
	}
}

// LoadOrCreateDefault loads config from a file or creates a default one if it doesn't exist.
// This is the recommended way to initialize configuration in the application.
func LoadOrCreateDefault(path string) (*Config, error) {
	// If file exists, load it
	if _, err := os.Stat(path); err == nil {
		return LoadConfig(path)
	}

	// Create default config
	cfg := DefaultConfig()

	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, constants.DirPermissions); err != nil {
		return nil, errors.Wrap(err, errors.ErrCategoryConfig, "DIR_CREATE_FAILED",
			fmt.Sprintf("Failed to create config directory: %s", dir))
	}

	// Save default config
	if err := cfg.Save(path); err != nil {
		return nil, err
	}

	return cfg, nil
}

// DefaultConfig returns a default configuration
func DefaultConfig() *Config {
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "honeybee-node"
	}

	// Default honeypot directory
	homeDir, _ := os.UserHomeDir()
	honeypotDir := filepath.Join(homeDir, ".honeybee", "honeypots")

	return &Config{
		Node: NodeConfig{
			Name:    hostname,
			Type:    "Full", // Default to Full for honeypot management
			Address: "0.0.0.0",
			Port:    8080,
		},
		Server: ServerConfig{
			Address:           "127.0.0.1:9001",
			HeartbeatInterval: 30,
			ReconnectDelay:    5,
			ConnectionTimeout: 10,
		},
		TLS: TLSConfig{
			Enabled:            true,
			InsecureSkipVerify: false,
			ServerName:         "honeybee-manager",
		},
		Auth: AuthConfig{
			TOTPEnabled: true,
		},
		Log: LogConfig{
			Level:  "info",
			Format: "text",
		},
		Honeypot: HoneypotConfig{
			Enabled:    true,
			BaseDir:    honeypotDir,
			DefaultSSH: 2222,
			DefaultTel: 2223,
		},
	}
}

// Save serializes the configuration to a YAML file.
// The file is created with secure permissions (0644).
func (c *Config) Save(path string) error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return errors.Wrap(err, errors.ErrCategoryConfig, "CONFIG_MARSHAL_FAILED",
			"Failed to marshal configuration to YAML")
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return errors.Wrap(err, errors.ErrCategoryConfig, "CONFIG_WRITE_FAILED",
			fmt.Sprintf("Failed to write config file: %s", path))
	}

	return nil
}

// Validate checks if the configuration is valid by validating all subsections
func (c *Config) Validate() error {
	if err := c.validateNode(); err != nil {
		return err
	}
	if err := c.validateServer(); err != nil {
		return err
	}
	if err := c.validateTLS(); err != nil {
		return err
	}
	if err := c.validateAuth(); err != nil {
		return err
	}
	if err := c.validateLog(); err != nil {
		return err
	}
	if err := c.validateHoneypot(); err != nil {
		return err
	}
	return nil
}

// validateNode validates node configuration
func (c *Config) validateNode() error {
	if c.Node.Name == "" {
		return errors.New(errors.ErrCategoryConfig, "EMPTY_NODE_NAME", "Node name cannot be empty")
	}
	
	if c.Node.Type != "Full" && c.Node.Type != "Agent" {
		return errors.New(errors.ErrCategoryConfig, "INVALID_NODE_TYPE",
			fmt.Sprintf("Invalid node type: %s (must be 'Full' or 'Agent')", c.Node.Type))
	}

	// Validate port if specified
	if c.Node.Port > 0 && c.Node.Port < 1024 {
		return errors.New(errors.ErrCategoryConfig, "INVALID_PORT",
			"Node port must be >= 1024 (or 0 for auto-assign)")
	}
	
	return nil
}

// validateServer validates server connection configuration
func (c *Config) validateServer() error {
	if c.Server.Address == "" {
		return errors.New(errors.ErrCategoryConfig, "EMPTY_SERVER_ADDR", "Server address is required")
	}
	
	// Try to parse as host:port
	host, port, err := net.SplitHostPort(c.Server.Address)
	if err != nil {
		// If no port specified, that's okay - we'll use default
		host = c.Server.Address
		port = ""
	}
	
	// Validate host is not empty
	if host == "" {
		return errors.New(errors.ErrCategoryConfig, "INVALID_SERVER_ADDR", 
			"Server address host cannot be empty")
	}
	
	// Validate port if present
	if port != "" {
		// Port will be validated by net.SplitHostPort already
	}

	// Validate intervals
	if c.Server.HeartbeatInterval <= 0 {
		return errors.New(errors.ErrCategoryConfig, "INVALID_HEARTBEAT", 
			"Heartbeat interval must be positive")
	}
	if c.Server.ReconnectDelay <= 0 {
		return errors.New(errors.ErrCategoryConfig, "INVALID_RECONNECT", 
			"Reconnect delay must be positive")
	}
	if c.Server.ConnectionTimeout <= 0 {
		return errors.New(errors.ErrCategoryConfig, "INVALID_TIMEOUT", 
			"Connection timeout must be positive")
	}
	
	return nil
	}

// validateTLS validates TLS configuration
func (c *Config) validateTLS() error {
	if !c.TLS.Enabled {
		return nil // TLS not enabled, nothing to validate
	}
	
	// Mutual TLS: both cert and key must be provided together
	if (c.TLS.CertFile != "" && c.TLS.KeyFile == "") || (c.TLS.KeyFile != "" && c.TLS.CertFile == "") {
		return errors.New(errors.ErrCategoryConfig, "INCOMPLETE_TLS_CONFIG",
			"Both TLS cert file and key file must be provided for mutual TLS")
	}
	
	// Check if files exist if paths are provided
	if c.TLS.CertFile != "" {
		if _, err := os.Stat(c.TLS.CertFile); os.IsNotExist(err) {
			return errors.New(errors.ErrCategoryConfig, "CERT_FILE_NOT_FOUND",
				fmt.Sprintf("TLS cert file not found: %s", c.TLS.CertFile))
		}
		}
	if c.TLS.KeyFile != "" {
		if _, err := os.Stat(c.TLS.KeyFile); os.IsNotExist(err) {
			return errors.New(errors.ErrCategoryConfig, "KEY_FILE_NOT_FOUND",
				fmt.Sprintf("TLS key file not found: %s", c.TLS.KeyFile))
		}
	}
	if c.TLS.CAFile != "" {
		if _, err := os.Stat(c.TLS.CAFile); os.IsNotExist(err) {
			return errors.New(errors.ErrCategoryConfig, "CA_FILE_NOT_FOUND",
				fmt.Sprintf("TLS CA file not found: %s", c.TLS.CAFile))
		}
	}
	
	// Warn if InsecureSkipVerify is true (don't fail, just warning)
	// The caller should log this warning
	
	return nil
}

// validateAuth validates authentication configuration
func (c *Config) validateAuth() error {
	// TOTP secret directory will be created if it doesn't exist
	// No validation needed here
	return nil
}

// validateLog validates logging configuration
func (c *Config) validateLog() error {
	// Validate log level
	validLevels := map[string]bool{
		"debug": true, "info": true, "warn": true, 
		"warning": true, "error": true, "fatal": true, "panic": true,
	}
	if !validLevels[strings.ToLower(c.Log.Level)] {
		return errors.New(errors.ErrCategoryConfig, "INVALID_LOG_LEVEL",
			fmt.Sprintf("Invalid log level: %s", c.Log.Level))
	}
	
	// Validate log format
	if c.Log.Format != "text" && c.Log.Format != "json" {
		return errors.New(errors.ErrCategoryConfig, "INVALID_LOG_FORMAT",
			fmt.Sprintf("Invalid log format: %s (must be 'text' or 'json')", c.Log.Format))
	}
	
	return nil
}

// validateHoneypot validates honeypot configuration
func (c *Config) validateHoneypot() error {
	if !c.Honeypot.Enabled {
		return nil // Honeypot management not enabled
	}
	
	if c.Honeypot.BaseDir == "" {
		return errors.New(errors.ErrCategoryConfig, "EMPTY_HONEYPOT_DIR",
			"Honeypot base directory is required when honeypot management is enabled")
	}
	
	// Validate ports
	if c.Honeypot.DefaultSSH > 0 && c.Honeypot.DefaultSSH < 1024 {
		return errors.New(errors.ErrCategoryConfig, "INVALID_SSH_PORT",
			"Default SSH port must be >= 1024 or 0 for disabled")
	}
	if c.Honeypot.DefaultTel > 0 && c.Honeypot.DefaultTel < 1024 {
		return errors.New(errors.ErrCategoryConfig, "INVALID_TELNET_PORT",
			"Default Telnet port must be >= 1024 or 0 for disabled")
	}
	
	// Check if base directory can be created
	if _, err := os.Stat(c.Honeypot.BaseDir); os.IsNotExist(err) {
		// Try to create it
		if err := os.MkdirAll(c.Honeypot.BaseDir, constants.DirPermissions); err != nil {
			return errors.Wrap(err, errors.ErrCategoryConfig, "CREATE_HONEYPOT_DIR_FAILED",
				fmt.Sprintf("Failed to create honeypot directory: %s", c.Honeypot.BaseDir))
		}
	}

	return nil
}
