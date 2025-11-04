package auth

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

const (
	// TOTPSecretFile stores the TOTP secret persistently
	TOTPSecretFile = ".honeybee_totp_secret"
	// TOTPIssuer is the name shown in authenticator apps
	TOTPIssuer = "HoneyBee"
)

// TOTPManager handles TOTP generation and validation
type TOTPManager struct {
	secret    string
	secretDir string
}

// NewTOTPManager creates a new TOTP manager
func NewTOTPManager(secretDir string) (*TOTPManager, error) {
	if secretDir == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("failed to get home directory: %w", err)
		}
		secretDir = filepath.Join(homeDir, ".config", "honeybee")
	}

	// Ensure directory exists
	if err := os.MkdirAll(secretDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create secret directory: %w", err)
	}

	return &TOTPManager{
		secretDir: secretDir,
	}, nil
}

// LoadOrGenerateSecret loads existing secret or generates a new one
func (tm *TOTPManager) LoadOrGenerateSecret() (string, bool, error) {
	secretPath := filepath.Join(tm.secretDir, TOTPSecretFile)

	// Try to load existing secret
	data, err := os.ReadFile(secretPath)
	if err == nil {
		secret := strings.TrimSpace(string(data))
		if secret != "" {
			tm.secret = secret
			return secret, false, nil // false = not newly generated
		}
	}

	// Generate new secret
	secret, err := tm.generateSecret()
	if err != nil {
		return "", false, fmt.Errorf("failed to generate secret: %w", err)
	}

	// Save secret
	if err := os.WriteFile(secretPath, []byte(secret), 0600); err != nil {
		return "", false, fmt.Errorf("failed to save secret: %w", err)
	}

	tm.secret = secret
	return secret, true, nil // true = newly generated
}

// generateSecret creates a new random TOTP secret
func (tm *TOTPManager) generateSecret() (string, error) {
	// Generate 20 random bytes (160 bits)
	secret := make([]byte, 20)
	if _, err := rand.Read(secret); err != nil {
		return "", err
	}

	// Encode as base32
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret), nil
}

// GenerateCode generates a TOTP code from the stored secret
func (tm *TOTPManager) GenerateCode() (string, error) {
	if tm.secret == "" {
		return "", fmt.Errorf("no TOTP secret loaded")
	}

	code, err := totp.GenerateCode(tm.secret, time.Now())
	if err != nil {
		return "", fmt.Errorf("failed to generate TOTP code: %w", err)
	}

	return code, nil
}

// ValidateCode validates a TOTP code against the stored secret
func (tm *TOTPManager) ValidateCode(code string) bool {
	if tm.secret == "" {
		return false
	}

	return totp.Validate(code, tm.secret)
}

// GetSecret returns the current TOTP secret
func (tm *TOTPManager) GetSecret() string {
	return tm.secret
}

// SetSecret sets the TOTP secret (used when receiving from server)
func (tm *TOTPManager) SetSecret(secret string) error {
	tm.secret = secret

	// Save to file
	secretPath := filepath.Join(tm.secretDir, TOTPSecretFile)
	if err := os.WriteFile(secretPath, []byte(secret), 0600); err != nil {
		return fmt.Errorf("failed to save secret: %w", err)
	}

	return nil
}

// GenerateProvisioningURI generates a URI for QR code generation
func (tm *TOTPManager) GenerateProvisioningURI(accountName string) (string, error) {
	if tm.secret == "" {
		return "", fmt.Errorf("no TOTP secret loaded")
	}

	key, err := otp.NewKeyFromURL(
		fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s",
			TOTPIssuer, accountName, tm.secret, TOTPIssuer),
	)
	if err != nil {
		return "", fmt.Errorf("failed to create provisioning URI: %w", err)
	}

	return key.String(), nil
}

// getCurrentTime returns the current time
func (tm *TOTPManager) getCurrentTime() time.Time {
	return time.Now()
}

// DeleteSecret removes the stored TOTP secret
func (tm *TOTPManager) DeleteSecret() error {
	secretPath := filepath.Join(tm.secretDir, TOTPSecretFile)
	if err := os.Remove(secretPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete secret: %w", err)
	}
	tm.secret = ""
	return nil
}

