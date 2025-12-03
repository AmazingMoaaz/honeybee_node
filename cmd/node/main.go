// Package main is the entry point for the HoneyBee Node application.
// It initializes the node, connects to the HoneyBee Core manager, and manages
// honeypot deployments on the local system.
//
// Usage:
//
//	honeybee-node [flags]
//
// Flags:
//
//	-config string
//	      Path to configuration file (default "configs/config.yaml")
//	-version
//	      Show version and exit
//	-gen-config
//	      Generate default configuration file and exit
//	-validate
//	      Validate configuration and exit
//	-debug
//	      Enable debug logging (overrides config)
//
// The node supports graceful shutdown on SIGINT and SIGTERM.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/honeybee/node/internal/client"
	"github.com/honeybee/node/internal/config"
	"github.com/honeybee/node/internal/constants"
	"github.com/honeybee/node/internal/logger"
)

// Application metadata
const (
	banner = `
 _   _                        ____             
| | | | ___  _ __   ___ _    | __ )  ___  ___ 
| |_| |/ _ \| '_ \ / _ \ | | |  _ \ / _ \/ _ \
|  _  | (_) | | | |  __/ |_| | |_) |  __/  __/
|_| |_|\___/|_| |_|\___|\__, |____/ \___|\___|
                        |___/  Node v%s
`
)

func main() {
	// Parse command line flags
	configPath := flag.String("config", "configs/config.yaml", "Path to configuration file")
	showVersion := flag.Bool("version", false, "Show version information and exit")
	genConfig := flag.Bool("gen-config", false, "Generate default configuration file and exit")
	validateConfig := flag.Bool("validate", false, "Validate configuration and exit")
	debugMode := flag.Bool("debug", false, "Enable debug logging (overrides config file)")
	flag.Parse()

	// Show version information
	if *showVersion {
		printVersion()
		os.Exit(0)
	}

	// Generate default configuration
	if *genConfig {
		if err := generateConfig(*configPath); err != nil {
			fmt.Fprintf(os.Stderr, "❌ Error generating config: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✅ Generated default configuration at: %s\n", *configPath)
		fmt.Println("\nNext steps:")
		fmt.Println("  1. Review and customize the configuration")
		fmt.Println("  2. Configure the server address")
		fmt.Println("  3. Run: honeybee-node -config " + *configPath)
		os.Exit(0)
	}

	// Print banner
	fmt.Printf(banner, constants.AppVersion)
	fmt.Println()

	// Load configuration
	cfg, err := config.LoadOrCreateDefault(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Error loading configuration: %v\n", err)
		os.Exit(1)
	}

	// Override log level if debug flag is set
	if *debugMode {
		cfg.Log.Level = "debug"
	}

	// Validate configuration and exit if requested
	if *validateConfig {
		validateAndExit(cfg, *configPath)
	}

	// Initialize logger
	if err := logger.Init(cfg.Log.Level, cfg.Log.Format, cfg.Log.File); err != nil {
		fmt.Fprintf(os.Stderr, "❌ Error initializing logger: %v\n", err)
		os.Exit(1)
	}

	logger.Infof("%s v%s starting...", constants.AppName, constants.AppVersion)
	logger.Infof("Configuration loaded from: %s", *configPath)
	logger.WithFields(logger.Fields{
		"node_name": cfg.Node.Name,
		"node_type": cfg.Node.Type,
		"server":    cfg.Server.Address,
		"tls":       cfg.TLS.Enabled,
		"totp":      cfg.Auth.TOTPEnabled,
		"honeypot":  cfg.Honeypot.Enabled,
	}).Info("Node configuration")

	// Warn about insecure configurations
	if !cfg.TLS.Enabled {
		logger.Warn("⚠️  TLS is disabled - communications are NOT encrypted!")
		logger.Warn("⚠️  This is NOT recommended for production use")
	}
	if cfg.TLS.Enabled && cfg.TLS.InsecureSkipVerify {
		logger.Warn("⚠️  TLS certificate verification is disabled")
		logger.Warn("⚠️  This is NOT recommended for production use")
	}

	// Create node client
	nodeClient, err := client.NewNodeClient(cfg)
	if err != nil {
		logger.Fatalf("❌ Failed to create node client: %v", err)
	}

	// Setup signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)

	// Run client in goroutine
	errChan := make(chan error, 1)
	go func() {
		errChan <- nodeClient.Run()
	}()

	logger.Info("✅ Node started successfully, running...")

	// Wait for shutdown signal or error
	select {
	case sig := <-sigChan:
		logger.Infof("📡 Received signal %v, initiating graceful shutdown...", sig)
		nodeClient.Stop()
		logger.Info("✅ Shutdown complete - goodbye! 🐝")

	case err := <-errChan:
		if err != nil {
			logger.Fatalf("❌ Node client error: %v", err)
		}
		logger.Info("Node client stopped normally")
	}
}

// printVersion prints detailed version information
func printVersion() {
	fmt.Printf("%s v%s\n", constants.AppName, constants.AppVersion)
	fmt.Printf("\n%s\n", constants.AppDescription)
	fmt.Printf("\nProtocol Version: %d\n", constants.ProtocolVersion)
	fmt.Printf("Build: Production\n")
}

// generateConfig generates a default configuration file
func generateConfig(path string) error {
	cfg := config.DefaultConfig()
	if err := cfg.Save(path); err != nil {
		return err
	}
	return nil
}

// validateAndExit validates configuration and exits with appropriate status code
func validateAndExit(cfg *config.Config, path string) {
	fmt.Printf("Validating configuration from: %s\n\n", path)

	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "❌ Configuration validation failed:\n")
		fmt.Fprintf(os.Stderr, "   %v\n\n", err)
		os.Exit(1)
	}

	fmt.Println("✅ Configuration is valid")
	fmt.Println("\nConfiguration summary:")
	fmt.Printf("  Node Name:    %s\n", cfg.Node.Name)
	fmt.Printf("  Node Type:    %s\n", cfg.Node.Type)
	fmt.Printf("  Server:       %s\n", cfg.Server.Address)
	fmt.Printf("  TLS Enabled:  %v\n", cfg.TLS.Enabled)
	fmt.Printf("  TOTP Enabled: %v\n", cfg.Auth.TOTPEnabled)
	fmt.Printf("  Honeypot:     %v\n", cfg.Honeypot.Enabled)
	fmt.Printf("  Log Level:    %s\n", cfg.Log.Level)
	os.Exit(0)
}
