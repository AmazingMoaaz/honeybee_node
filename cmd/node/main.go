package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/honeybee/node/internal/client"
	"github.com/honeybee/node/internal/config"
	"github.com/honeybee/node/internal/logger"
)

const (
	version = "1.0.0"
	banner  = `
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
	showVersion := flag.Bool("version", false, "Show version and exit")
	genConfig := flag.Bool("gen-config", false, "Generate default configuration file")
	flag.Parse()

	// Show version
	if *showVersion {
		fmt.Printf("HoneyBee Node v%s\n", version)
		os.Exit(0)
	}

	// Generate config
	if *genConfig {
		cfg := config.DefaultConfig()
		if err := cfg.Save(*configPath); err != nil {
			fmt.Fprintf(os.Stderr, "Error generating config: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Generated default configuration at: %s\n", *configPath)
		os.Exit(0)
	}

	// Print banner
	fmt.Printf(banner, version)
	fmt.Println()

	// Load configuration
	cfg, err := config.LoadOrCreateDefault(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading configuration: %v\n", err)
		os.Exit(1)
	}

	// Initialize logger
	if err := logger.Init(cfg.Log.Level, cfg.Log.Format, cfg.Log.File); err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing logger: %v\n", err)
		os.Exit(1)
	}

	logger.Infof("HoneyBee Node v%s starting...", version)
	logger.Infof("Configuration loaded from: %s", *configPath)

	// Create node client
	nodeClient, err := client.NewNodeClient(cfg)
	if err != nil {
		logger.Fatalf("Failed to create node client: %v", err)
	}

	// Setup signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)

	// Run client in goroutine
	errChan := make(chan error, 1)
	go func() {
		errChan <- nodeClient.Run()
	}()

	// Wait for shutdown signal or error
	select {
	case sig := <-sigChan:
		logger.Infof("Received signal %v, shutting down...", sig)
		nodeClient.Stop()
		logger.Info("Shutdown complete")

	case err := <-errChan:
		if err != nil {
			logger.Fatalf("Node client error: %v", err)
		}
	}
}
