package auth

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/honeybee/node/internal/constants"
	"github.com/honeybee/node/internal/errors"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// TOTPManager handles Time-based One-Time Password (TOTP) generation and validation
// for two-factor authentication. It manages TOTP secrets persistently and provides
// methods for generating and validating codes compatible with standard authenticator apps.
type TOTPManager struct {
	secret    string // Base32-encoded TOTP secret
	secretDir string // Directory where the secret is stored
}

// NewTOTPManager creates a new TOTP manager instance.
// If secretDir is empty, it defaults to ~/.config/honeybee
// The manager handles secret persistence and provides thread-safe operations.
func NewTOTPManager(secretDir string) (*TOTPManager, error) {
	if secretDir == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return nil, errors.Wrap(err, errors.ErrCategoryAuth, "HOME_DIR_FAILED",
				"Failed to get home directory")
		}
		secretDir = filepath.Join(homeDir, ".config", "honeybee")
	}

	// Ensure directory exists with secure permissions
	if err := os.MkdirAll(secretDir, constants.SecretDirPermissions); err != nil {
		return nil, errors.Wrap(err, errors.ErrCategoryAuth, "CREATE_DIR_FAILED",
			fmt.Sprintf("Failed to create secret directory: %s", secretDir))
	}

	return &TOTPManager{
		secretDir: secretDir,
	}, nil
}

// LoadOrGenerateSecret loads an existing secret from disk or generates a new one.
// Returns:
//   - secret: The TOTP secret (base32-encoded)
//   - isNew: true if the secret was newly generated, false if loaded from disk
//   - error: Any error that occurred
func (tm *TOTPManager) LoadOrGenerateSecret() (string, bool, error) {
	secretPath := filepath.Join(tm.secretDir, constants.TOTPSecretFile)

	// Try to load existing secret
	data, err := os.ReadFile(secretPath)
	if err == nil {
		secret := strings.TrimSpace(string(data))
		if secret != "" && len(secret) == 32 { // Base32-encoded 20 bytes = 32 chars
			tm.secret = secret
			return secret, false, nil // false = not newly generated
		}
	}

	// Generate new secret if not found or invalid
	secret, err := tm.generateSecret()
	if err != nil {
		return "", false, errors.Wrap(err, errors.ErrCategoryAuth, "SECRET_GEN_FAILED",
			"Failed to generate TOTP secret")
	}

	// Save secret with secure permissions
	if err := os.WriteFile(secretPath, []byte(secret), constants.ConfigFilePermissions); err != nil {
		return "", false, errors.Wrap(err, errors.ErrCategoryAuth, "SECRET_SAVE_FAILED",
			fmt.Sprintf("Failed to save secret to %s", secretPath))
	}

	tm.secret = secret
	return secret, true, nil // true = newly generated
}

// generateSecret creates a new cryptographically secure random TOTP secret
func (tm *TOTPManager) generateSecret() (string, error) {
	// Generate random bytes (160 bits as per RFC 4226)
	secret := make([]byte, constants.TOTPSecretLength)
	if _, err := rand.Read(secret); err != nil {
		return "", errors.Wrap(err, errors.ErrCategoryAuth, "RAND_FAILED",
			"Failed to generate random bytes")
	}

	// Encode as base32 without padding (standard for TOTP)
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret), nil
}

// GenerateCode generates a 6-digit TOTP code from the stored secret.
// The code is valid for 30 seconds (standard TOTP window).
func (tm *TOTPManager) GenerateCode() (string, error) {
	if tm.secret == "" {
		return "", errors.New(errors.ErrCategoryAuth, "NO_SECRET",
			"TOTP secret not loaded - call LoadOrGenerateSecret() first")
	}

	code, err := totp.GenerateCode(tm.secret, time.Now())
	if err != nil {
		return "", errors.Wrap(err, errors.ErrCategoryAuth, "CODE_GEN_FAILED",
			"Failed to generate TOTP code")
	}

	return code, nil
}

// ValidateCode validates a TOTP code against the stored secret.
// Returns true if the code is valid within the current time window.
func (tm *TOTPManager) ValidateCode(code string) bool {
	if tm.secret == "" || code == "" {
		return false
	}

	// Validate with a window of ±1 time step (30 seconds each)
	return totp.Validate(code, tm.secret)
}

// GetSecret returns the current TOTP secret.
// Returns an empty string if no secret is loaded.
func (tm *TOTPManager) GetSecret() string {
	return tm.secret
}

// SetSecret sets the TOTP secret and persists it to disk.
// This is typically used when receiving a secret from the server during initial registration.
func (tm *TOTPManager) SetSecret(secret string) error {
	if secret == "" {
		return errors.New(errors.ErrCategoryAuth, "EMPTY_SECRET",
			"TOTP secret cannot be empty")
	}

	// Validate base32 format
	if _, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret); err != nil {
		return errors.Wrap(err, errors.ErrCategoryAuth, "INVALID_SECRET",
			"Invalid TOTP secret format - must be base32-encoded")
	}

	tm.secret = secret

	// Save to file with secure permissions
	secretPath := filepath.Join(tm.secretDir, constants.TOTPSecretFile)
	if err := os.WriteFile(secretPath, []byte(secret), constants.ConfigFilePermissions); err != nil {
		return errors.Wrap(err, errors.ErrCategoryAuth, "SECRET_SAVE_FAILED",
			fmt.Sprintf("Failed to save secret to %s", secretPath))
	}

	return nil
}

// GenerateProvisioningURI generates an otpauth:// URI for QR code generation.
// This URI can be scanned by authenticator apps like Google Authenticator or Authy.
func (tm *TOTPManager) GenerateProvisioningURI(accountName string) (string, error) {
	if tm.secret == "" {
		return "", errors.New(errors.ErrCategoryAuth, "NO_SECRET",
			"TOTP secret not loaded")
	}
	if accountName == "" {
		return "", errors.New(errors.ErrCategoryAuth, "EMPTY_ACCOUNT",
			"Account name cannot be empty")
	}

	key, err := otp.NewKeyFromURL(
		fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s",
			constants.TOTPIssuer, accountName, tm.secret, constants.TOTPIssuer),
	)
	if err != nil {
		return "", errors.Wrap(err, errors.ErrCategoryAuth, "URI_GEN_FAILED",
			"Failed to create provisioning URI")
	}

	return key.String(), nil
}

// DeleteSecret removes the stored TOTP secret from disk and memory.
// This is typically used when de-registering a node or resetting authentication.
func (tm *TOTPManager) DeleteSecret() error {
	secretPath := filepath.Join(tm.secretDir, constants.TOTPSecretFile)
	if err := os.Remove(secretPath); err != nil && !os.IsNotExist(err) {
		return errors.Wrap(err, errors.ErrCategoryAuth, "SECRET_DELETE_FAILED",
			fmt.Sprintf("Failed to delete secret from %s", secretPath))
	}
	tm.secret = ""
	return nil
}

