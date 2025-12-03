// Package logger provides centralized logging functionality for the HoneyBee Node.
// It wraps logrus to provide structured logging with consistent formatting,
// contextual fields, and support for multiple output destinations.
//
// Usage:
//
//	logger.Init("info", "text", "")
//	logger.Info("Application started")
//	logger.WithFields(logger.Fields{"user": "admin"}).Info("User logged in")
package logger

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/honeybee/node/internal/constants"
	"github.com/sirupsen/logrus"
)

var (
	log  *logrus.Logger
	once sync.Once
)

// Fields is an alias for logrus.Fields for convenience
type Fields = logrus.Fields

// Init initializes the logger with the specified configuration.
// This should be called once at application startup.
// Parameters:
//   - level: Log level (debug, info, warn, error, fatal, panic)
//   - format: Log format (text or json)
//   - logFile: Optional file path for log output (empty string logs to stdout only)
func Init(level, format, logFile string) error {
	var initErr error

	once.Do(func() {
		log = logrus.New()

		// Set log level
		lvl, err := logrus.ParseLevel(level)
		if err != nil {
			initErr = fmt.Errorf("invalid log level '%s': %w", level, err)
			return
		}
		log.SetLevel(lvl)

		// Set format
		if format == "json" {
			log.SetFormatter(&logrus.JSONFormatter{
				TimestampFormat:  constants.LogTimestampFormat,
				DisableTimestamp: false,
				PrettyPrint:      false,
			})
		} else {
			log.SetFormatter(&logrus.TextFormatter{
				FullTimestamp:   true,
				TimestampFormat: "2006-01-02 15:04:05",
				ForceColors:     true,
				DisableColors:   false,
			})
		}

		// Set output
		if logFile != "" {
			// Ensure directory exists
			dir := filepath.Dir(logFile)
			if err := os.MkdirAll(dir, constants.DirPermissions); err != nil {
				initErr = fmt.Errorf("failed to create log directory: %w", err)
				return
			}

			file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
			if err != nil {
				initErr = fmt.Errorf("failed to open log file: %w", err)
				return
			}

			// Write to both file and stdout for better debugging
			log.SetOutput(io.MultiWriter(os.Stdout, file))
		} else {
			log.SetOutput(os.Stdout)
		}

		// Add default fields
		log.WithFields(logrus.Fields{
			"app":     constants.AppName,
			"version": constants.AppVersion,
		})
	})

	return initErr
}

// GetLogger returns the logger instance.
// If Init() has not been called, returns a default logger.
func GetLogger() *logrus.Logger {
	if log == nil {
		// Return a default logger if Init wasn't called
		once.Do(func() {
			log = logrus.New()
			log.SetLevel(logrus.InfoLevel)
			log.SetFormatter(&logrus.TextFormatter{
				FullTimestamp: true,
				ForceColors:   true,
			})
		})
	}
	return log
}

// WithField creates a logger entry with a single field for structured logging
func WithField(key string, value interface{}) *logrus.Entry {
	return GetLogger().WithField(key, value)
}

// WithFields creates a logger entry with multiple fields for structured logging
func WithFields(fields logrus.Fields) *logrus.Entry {
	return GetLogger().WithFields(fields)
}

// WithError creates a logger entry with an error field
func WithError(err error) *logrus.Entry {
	return GetLogger().WithError(err)
}

// WithNodeContext creates a logger entry with node-specific context
func WithNodeContext(nodeID uint64, nodeName string) *logrus.Entry {
	return GetLogger().WithFields(logrus.Fields{
		constants.LogFieldNodeID:   nodeID,
		constants.LogFieldNodeName: nodeName,
	})
}

// WithHoneypotContext creates a logger entry with honeypot-specific context
func WithHoneypotContext(honeypotID, honeypotType string) *logrus.Entry {
	return GetLogger().WithFields(logrus.Fields{
		constants.LogFieldHoneypotID:   honeypotID,
		constants.LogFieldHoneypotType: honeypotType,
	})
}

// SetLevel changes the log level dynamically
func SetLevel(level string) error {
	lvl, err := logrus.ParseLevel(level)
	if err != nil {
		return fmt.Errorf("invalid log level '%s': %w", level, err)
	}
	GetLogger().SetLevel(lvl)
	return nil
}

// GetLevel returns the current log level
func GetLevel() string {
	return GetLogger().GetLevel().String()
}

// Debug logs a debug message
func Debug(args ...interface{}) {
	GetLogger().Debug(args...)
}

// Debugf logs a formatted debug message
func Debugf(format string, args ...interface{}) {
	GetLogger().Debugf(format, args...)
}

// Info logs an info message
func Info(args ...interface{}) {
	GetLogger().Info(args...)
}

// Infof logs a formatted info message
func Infof(format string, args ...interface{}) {
	GetLogger().Infof(format, args...)
}

// Warn logs a warning message
func Warn(args ...interface{}) {
	GetLogger().Warn(args...)
}

// Warnf logs a formatted warning message
func Warnf(format string, args ...interface{}) {
	GetLogger().Warnf(format, args...)
}

// Error logs an error message
func Error(args ...interface{}) {
	GetLogger().Error(args...)
}

// Errorf logs a formatted error message
func Errorf(format string, args ...interface{}) {
	GetLogger().Errorf(format, args...)
}

// Fatal logs a fatal message and exits
func Fatal(args ...interface{}) {
	GetLogger().Fatal(args...)
}

// Fatalf logs a formatted fatal message and exits
func Fatalf(format string, args ...interface{}) {
	GetLogger().Fatalf(format, args...)
}
