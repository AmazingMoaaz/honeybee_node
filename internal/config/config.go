package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config represents the node configuration
type Config struct {
	Node   NodeConfig   `yaml:"node"`
	Server ServerConfig `yaml:"server"`
	TLS    TLSConfig    `yaml:"tls"`
	Auth   AuthConfig   `yaml:"auth"`
	Log    LogConfig    `yaml:"log"`
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

// LoadConfig loads configuration from a file
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return &cfg, nil
}

// LoadOrCreateDefault loads config or creates a default one
func LoadOrCreateDefault(path string) (*Config, error) {
	// If file exists, load it
	if _, err := os.Stat(path); err == nil {
		return LoadConfig(path)
	}

	// Create default config
	cfg := DefaultConfig()

	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create config directory: %w", err)
	}

	// Save default config
	if err := cfg.Save(path); err != nil {
		return nil, fmt.Errorf("failed to save default config: %w", err)
	}

	return cfg, nil
}

// DefaultConfig returns a default configuration
func DefaultConfig() *Config {
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "honeybee-node"
	}

	return &Config{
		Node: NodeConfig{
			Name:    hostname,
			Type:    "Agent",
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
	}
}

// Save saves the configuration to a file
func (c *Config) Save(path string) error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	// Validate node type
	if c.Node.Type != "Full" && c.Node.Type != "Agent" {
		return fmt.Errorf("invalid node type: %s (must be 'Full' or 'Agent')", c.Node.Type)
	}

	// Validate server address
	if c.Server.Address == "" {
		return fmt.Errorf("server address is required")
	}

	// Validate intervals
	if c.Server.HeartbeatInterval <= 0 {
		return fmt.Errorf("heartbeat interval must be positive")
	}

	if c.Server.ReconnectDelay <= 0 {
		return fmt.Errorf("reconnect delay must be positive")
	}

	// Validate TLS settings
	if c.TLS.Enabled {
		if c.TLS.CertFile != "" && c.TLS.KeyFile == "" {
			return fmt.Errorf("TLS key file required when cert file is specified")
		}
		if c.TLS.KeyFile != "" && c.TLS.CertFile == "" {
			return fmt.Errorf("TLS cert file required when key file is specified")
		}
	}

	// Validate log level
	validLevels := map[string]bool{"debug": true, "info": true, "warn": true, "error": true}
	if !validLevels[c.Log.Level] {
		return fmt.Errorf("invalid log level: %s", c.Log.Level)
	}

	return nil
}
