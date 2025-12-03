// Package errors provides custom error types and error handling utilities
// for the HoneyBee Node application. This package centralizes error definitions
// and provides structured error information for better error handling and logging.
package errors

import (
	"errors"
	"fmt"
)

// Error categories define the type of error that occurred
const (
	// ErrCategoryConfig indicates a configuration error
	ErrCategoryConfig = "CONFIG"
	// ErrCategoryNetwork indicates a network-related error
	ErrCategoryNetwork = "NETWORK"
	// ErrCategoryAuth indicates an authentication error
	ErrCategoryAuth = "AUTH"
	// ErrCategoryProtocol indicates a protocol error
	ErrCategoryProtocol = "PROTOCOL"
	// ErrCategoryHoneypot indicates a honeypot management error
	ErrCategoryHoneypot = "HONEYPOT"
	// ErrCategoryInternal indicates an internal system error
	ErrCategoryInternal = "INTERNAL"
)

// NodeError represents a structured error with additional context
type NodeError struct {
	Category string // Error category (Config, Network, Auth, etc.)
	Code     string // Machine-readable error code
	Message  string // Human-readable error message
	Err      error  // Underlying error (if any)
}

// Error implements the error interface
func (e *NodeError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("[%s:%s] %s: %v", e.Category, e.Code, e.Message, e.Err)
	}
	return fmt.Sprintf("[%s:%s] %s", e.Category, e.Code, e.Message)
}

// Unwrap returns the underlying error for error chain unwrapping
func (e *NodeError) Unwrap() error {
	return e.Err
}

// Is checks if the target error matches this error's code
func (e *NodeError) Is(target error) bool {
	t, ok := target.(*NodeError)
	if !ok {
		return false
	}
	return e.Code == t.Code
}

// =============================================================================
// Error Constructors
// =============================================================================

// New creates a new NodeError
func New(category, code, message string) *NodeError {
	return &NodeError{
		Category: category,
		Code:     code,
		Message:  message,
	}
}

// Wrap wraps an existing error with additional context
func Wrap(err error, category, code, message string) *NodeError {
	return &NodeError{
		Category: category,
		Code:     code,
		Message:  message,
		Err:      err,
	}
}

// =============================================================================
// Common Errors
// =============================================================================

// Configuration errors
var (
	ErrInvalidConfig = New(ErrCategoryConfig, "INVALID_CONFIG", "Invalid configuration")
	ErrMissingConfig = New(ErrCategoryConfig, "MISSING_CONFIG", "Required configuration missing")
	ErrConfigLoad    = New(ErrCategoryConfig, "CONFIG_LOAD", "Failed to load configuration")
	ErrConfigSave    = New(ErrCategoryConfig, "CONFIG_SAVE", "Failed to save configuration")
)

// Network errors
var (
	ErrConnectionFailed  = New(ErrCategoryNetwork, "CONN_FAILED", "Connection failed")
	ErrConnectionTimeout = New(ErrCategoryNetwork, "CONN_TIMEOUT", "Connection timeout")
	ErrConnectionClosed  = New(ErrCategoryNetwork, "CONN_CLOSED", "Connection closed")
	ErrInvalidAddress    = New(ErrCategoryNetwork, "INVALID_ADDR", "Invalid address")
)

// Authentication errors
var (
	ErrAuthFailed         = New(ErrCategoryAuth, "AUTH_FAILED", "Authentication failed")
	ErrInvalidTOTP        = New(ErrCategoryAuth, "INVALID_TOTP", "Invalid TOTP code")
	ErrTLSFailed          = New(ErrCategoryAuth, "TLS_FAILED", "TLS handshake failed")
	ErrCertificateLoad    = New(ErrCategoryAuth, "CERT_LOAD", "Failed to load certificate")
	ErrInvalidCertificate = New(ErrCategoryAuth, "INVALID_CERT", "Invalid certificate")
)

// Protocol errors
var (
	ErrProtocolVersion    = New(ErrCategoryProtocol, "VERSION_MISMATCH", "Protocol version mismatch")
	ErrInvalidMessage     = New(ErrCategoryProtocol, "INVALID_MSG", "Invalid message format")
	ErrMessageEncode      = New(ErrCategoryProtocol, "MSG_ENCODE", "Failed to encode message")
	ErrMessageDecode      = New(ErrCategoryProtocol, "MSG_DECODE", "Failed to decode message")
	ErrRegistrationFailed = New(ErrCategoryProtocol, "REG_FAILED", "Node registration failed")
)

// Honeypot errors
var (
	ErrHoneypotNotFound      = New(ErrCategoryHoneypot, "NOT_FOUND", "Honeypot not found")
	ErrHoneypotAlreadyExists = New(ErrCategoryHoneypot, "ALREADY_EXISTS", "Honeypot already exists")
	ErrHoneypotInstallFailed = New(ErrCategoryHoneypot, "INSTALL_FAILED", "Honeypot installation failed")
	ErrHoneypotStartFailed   = New(ErrCategoryHoneypot, "START_FAILED", "Failed to start honeypot")
	ErrHoneypotStopFailed    = New(ErrCategoryHoneypot, "STOP_FAILED", "Failed to stop honeypot")
	ErrHoneypotNotRunning    = New(ErrCategoryHoneypot, "NOT_RUNNING", "Honeypot is not running")
	ErrHoneypotNotStopped    = New(ErrCategoryHoneypot, "NOT_STOPPED", "Honeypot is not stopped")
	ErrInvalidHoneypotType   = New(ErrCategoryHoneypot, "INVALID_TYPE", "Invalid honeypot type")
)

// Internal errors
var (
	ErrInternal        = New(ErrCategoryInternal, "INTERNAL", "Internal error")
	ErrNotImplemented  = New(ErrCategoryInternal, "NOT_IMPLEMENTED", "Feature not implemented")
	ErrInvalidState    = New(ErrCategoryInternal, "INVALID_STATE", "Invalid state")
	ErrOperationFailed = New(ErrCategoryInternal, "OP_FAILED", "Operation failed")
)

// =============================================================================
// Helper Functions
// =============================================================================

// IsCategory checks if an error belongs to a specific category
func IsCategory(err error, category string) bool {
	var nodeErr *NodeError
	if errors.As(err, &nodeErr) {
		return nodeErr.Category == category
	}
	return false
}

// GetCategory returns the error category or empty string if not a NodeError
func GetCategory(err error) string {
	var nodeErr *NodeError
	if errors.As(err, &nodeErr) {
		return nodeErr.Category
	}
	return ""
}

// GetCode returns the error code or empty string if not a NodeError
func GetCode(err error) string {
	var nodeErr *NodeError
	if errors.As(err, &nodeErr) {
		return nodeErr.Code
	}
	return ""
}
