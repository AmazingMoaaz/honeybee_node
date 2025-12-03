// Package auth provides authentication and encryption mechanisms for secure
// communication between HoneyBee nodes and the core manager. It supports
// TLS 1.3 with strong cipher suites and TOTP-based two-factor authentication.
package auth

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"github.com/honeybee/node/internal/errors"
)

// TLSConfig holds TLS configuration options for secure communication
type TLSConfig struct {
	CertFile           string // Path to client certificate file (for mutual TLS)
	KeyFile            string // Path to client private key file (for mutual TLS)
	CAFile             string // Path to CA certificate file (for server verification)
	InsecureSkipVerify bool   // Whether to skip certificate verification (WARNING: insecure)
	ServerName         string // Expected server name for SNI and certificate validation
}

// Validate checks if the TLS configuration is valid
func (cfg *TLSConfig) Validate() error {
	// If cert is provided, key must also be provided
	if (cfg.CertFile != "" && cfg.KeyFile == "") || (cfg.CertFile == "" && cfg.KeyFile != "") {
		return errors.New(errors.ErrCategoryAuth, "INVALID_TLS_CONFIG",
			"Both certificate and key file must be provided for mutual TLS")
	}

	// Check if files exist
	if cfg.CertFile != "" {
		if _, err := os.Stat(cfg.CertFile); err != nil {
			return errors.Wrap(err, errors.ErrCategoryAuth, "CERT_FILE_NOT_FOUND",
				fmt.Sprintf("Certificate file not found: %s", cfg.CertFile))
		}
	}
	if cfg.KeyFile != "" {
		if _, err := os.Stat(cfg.KeyFile); err != nil {
			return errors.Wrap(err, errors.ErrCategoryAuth, "KEY_FILE_NOT_FOUND",
				fmt.Sprintf("Key file not found: %s", cfg.KeyFile))
		}
	}
	if cfg.CAFile != "" {
		if _, err := os.Stat(cfg.CAFile); err != nil {
			return errors.Wrap(err, errors.ErrCategoryAuth, "CA_FILE_NOT_FOUND",
				fmt.Sprintf("CA file not found: %s", cfg.CAFile))
		}
	}

	return nil
}

// LoadTLSConfig creates a TLS configuration from the provided options.
// It supports:
//   - Mutual TLS with client certificates
//   - Custom CA certificates for server validation
//   - TLS 1.3 with strong cipher suites
//
// Returns an error if certificate loading fails or configuration is invalid.
func LoadTLSConfig(cfg *TLSConfig) (*tls.Config, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	tlsConfig := &tls.Config{
		InsecureSkipVerify: cfg.InsecureSkipVerify,
		ServerName:         cfg.ServerName,
		MinVersion:         tls.VersionTLS13, // Use TLS 1.3 for best security
		MaxVersion:         tls.VersionTLS13, // Only allow TLS 1.3
		// TLS 1.3 cipher suites (these are the only supported ones)
		CipherSuites: []uint16{
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_AES_128_GCM_SHA256,
		},
		PreferServerCipherSuites: false,
		SessionTicketsDisabled:   false,
		Renegotiation:            tls.RenegotiateNever,
	}

	// Load client certificate if provided (mutual TLS)
	if cfg.CertFile != "" && cfg.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, errors.Wrap(err, errors.ErrCategoryAuth, "CERT_LOAD_FAILED",
				"Failed to load client certificate")
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	// Load CA certificate if provided for server verification
	if cfg.CAFile != "" {
		caCert, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, errors.Wrap(err, errors.ErrCategoryAuth, "CA_READ_FAILED",
				fmt.Sprintf("Failed to read CA certificate from %s", cfg.CAFile))
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, errors.New(errors.ErrCategoryAuth, "CA_PARSE_FAILED",
				"Failed to parse CA certificate - invalid PEM format")
		}

		tlsConfig.RootCAs = caCertPool
	}

	return tlsConfig, nil
}

// GenerateSelfSignedConfig creates a basic TLS config for development
// In production, use proper certificates from a CA
func GenerateSelfSignedConfig(serverName string) *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true, // Only for development!
		ServerName:         serverName,
		MinVersion:         tls.VersionTLS13,
	}
}
