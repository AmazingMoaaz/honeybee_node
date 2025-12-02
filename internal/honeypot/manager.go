package honeypot

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/honeybee/node/internal/logger"
	"github.com/honeybee/node/internal/protocol"
)

// HoneypotManager manages honeypot installations and lifecycle
type HoneypotManager struct {
	baseDir       string
	honeypots     map[string]*HoneypotInstance
	mu            sync.RWMutex
	eventChan     chan *protocol.HoneypotEvent
	nodeID        uint64
	eventListener net.Listener
	listenerPort  int
	ctx           context.Context
	cancel        context.CancelFunc
}

// HoneypotInstance represents a single honeypot installation
type HoneypotInstance struct {
	ID          string
	Type        string
	GitURL      string
	InstallPath string
	Status      protocol.HoneypotStatus
	SSHPort     uint16
	TelnetPort  uint16
	Process     *exec.Cmd
	cancelFunc  context.CancelFunc
	mu          sync.Mutex
}

// NewHoneypotManager creates a new honeypot manager
func NewHoneypotManager(baseDir string, nodeID uint64) (*HoneypotManager, error) {
	// Create base directory if it doesn't exist
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create honeypot base directory: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &HoneypotManager{
		baseDir:   baseDir,
		honeypots: make(map[string]*HoneypotInstance),
		eventChan: make(chan *protocol.HoneypotEvent, 1000),
		nodeID:    nodeID,
		ctx:       ctx,
		cancel:    cancel,
	}, nil
}

// Start starts the honeypot manager and event listener
func (hm *HoneypotManager) Start() error {
	// Start the event listener for receiving honeypot events via socket
	if err := hm.startEventListener(); err != nil {
		return fmt.Errorf("failed to start event listener: %w", err)
	}

	logger.Infof("HoneypotManager started, event listener on port %d", hm.listenerPort)
	return nil
}

// Stop stops all honeypots and the manager
func (hm *HoneypotManager) Stop() {
	hm.cancel()

	// Stop all honeypots
	hm.mu.RLock()
	for _, hp := range hm.honeypots {
		hm.stopHoneypot(hp)
	}
	hm.mu.RUnlock()

	// Close event listener
	if hm.eventListener != nil {
		hm.eventListener.Close()
	}

	close(hm.eventChan)
	logger.Info("HoneypotManager stopped")
}

// EventChannel returns the channel for honeypot events
func (hm *HoneypotManager) EventChannel() <-chan *protocol.HoneypotEvent {
	return hm.eventChan
}

// InstallHoneypot installs a honeypot from a Git repository
func (hm *HoneypotManager) InstallHoneypot(cmd *protocol.InstallHoneypotCmd) error {
	hm.mu.Lock()
	defer hm.mu.Unlock()

	// Check if honeypot already exists
	if _, exists := hm.honeypots[cmd.HoneypotID]; exists {
		return fmt.Errorf("honeypot %s already exists", cmd.HoneypotID)
	}

	installPath := filepath.Join(hm.baseDir, cmd.HoneypotID)

	instance := &HoneypotInstance{
		ID:          cmd.HoneypotID,
		Type:        cmd.HoneypotType,
		GitURL:      cmd.GitURL,
		InstallPath: installPath,
		Status:      protocol.HoneypotStatusInstalling,
		SSHPort:     cmd.SSHPort,
		TelnetPort:  cmd.TelnetPort,
	}

	// Set default ports
	if instance.SSHPort == 0 {
		instance.SSHPort = 2222
	}
	if instance.TelnetPort == 0 {
		instance.TelnetPort = 2223
	}

	hm.honeypots[cmd.HoneypotID] = instance

	// Install honeypot in background
	go hm.installHoneypotAsync(instance, cmd)

	return nil
}

// PotStoreURL is the official HoneyBee PotStore repository
const PotStoreURL = "https://github.com/H0neyBe/honeybee_potstore.git"

// installHoneypotAsync performs the actual installation asynchronously
func (hm *HoneypotManager) installHoneypotAsync(instance *HoneypotInstance, cmd *protocol.InstallHoneypotCmd) {
	logger.Infof("Installing honeypot %s (type: %s)", instance.ID, instance.Type)

	// Send installing status
	hm.sendStatusUpdate(instance, "Installing from HoneyBee PotStore...")

	// Determine source: use custom git_url if provided, otherwise use PotStore
	gitURL := cmd.GitURL
	if gitURL == "" {
		gitURL = PotStoreURL
	}

	branch := cmd.GitBranch
	if branch == "" {
		branch = "main"
	}

	// Clone the repository
	tempPath := instance.InstallPath
	if gitURL == PotStoreURL {
		// Clone potstore to temp location, then move honeypot subdirectory
		tempPath = filepath.Join(hm.baseDir, ".potstore-temp")
	}

	gitArgs := []string{"clone", "--depth", "1", "--branch", branch, gitURL, tempPath}
	gitCmd := exec.CommandContext(hm.ctx, "git", gitArgs...)
	gitCmd.Stdout = os.Stdout
	gitCmd.Stderr = os.Stderr

	if err := gitCmd.Run(); err != nil {
		logger.Errorf("Failed to clone repository: %v", err)
		instance.Status = protocol.HoneypotStatusFailed
		hm.sendStatusUpdate(instance, fmt.Sprintf("Git clone failed: %v", err))
		return
	}

	// If using PotStore, move the specific honeypot directory
	if gitURL == PotStoreURL {
		honeypotSrcPath := filepath.Join(tempPath, instance.Type)
		if _, err := os.Stat(honeypotSrcPath); os.IsNotExist(err) {
			// Try with version suffix (e.g., cowrie-2.9.0)
			entries, _ := filepath.Glob(filepath.Join(tempPath, instance.Type+"*"))
			if len(entries) > 0 {
				honeypotSrcPath = entries[0]
			} else {
				logger.Errorf("Honeypot %s not found in PotStore", instance.Type)
				instance.Status = protocol.HoneypotStatusFailed
				hm.sendStatusUpdate(instance, fmt.Sprintf("Honeypot %s not found in PotStore", instance.Type))
				os.RemoveAll(tempPath)
				return
			}
		}

		// Move honeypot to final location
		if err := os.Rename(honeypotSrcPath, instance.InstallPath); err != nil {
			// If rename fails (cross-device), try copy
			cpCmd := exec.CommandContext(hm.ctx, "cp", "-r", honeypotSrcPath, instance.InstallPath)
			if runtime.GOOS == "windows" {
				cpCmd = exec.CommandContext(hm.ctx, "xcopy", honeypotSrcPath, instance.InstallPath, "/E", "/I", "/H")
			}
			if err := cpCmd.Run(); err != nil {
				logger.Errorf("Failed to copy honeypot: %v", err)
				instance.Status = protocol.HoneypotStatusFailed
				hm.sendStatusUpdate(instance, fmt.Sprintf("Failed to copy honeypot: %v", err))
				os.RemoveAll(tempPath)
				return
			}
		}

		// Cleanup temp potstore
		os.RemoveAll(tempPath)
	}

	logger.Infof("Installed honeypot to %s", instance.InstallPath)

	// Run honeypot-specific setup
	if err := hm.setupHoneypot(instance, cmd.Config); err != nil {
		logger.Errorf("Failed to setup honeypot: %v", err)
		instance.Status = protocol.HoneypotStatusFailed
		hm.sendStatusUpdate(instance, fmt.Sprintf("Setup failed: %v", err))
		return
	}

	instance.Status = protocol.HoneypotStatusStopped
	hm.sendStatusUpdate(instance, "Installation complete")

	logger.Infof("Honeypot %s installed successfully", instance.ID)

	// Auto-start if requested
	if cmd.AutoStart {
		if err := hm.StartHoneypot(cmd.HoneypotID); err != nil {
			logger.Errorf("Failed to auto-start honeypot: %v", err)
		}
	}
}

// setupHoneypot performs honeypot-specific setup (virtualenv, config, etc.)
func (hm *HoneypotManager) setupHoneypot(instance *HoneypotInstance, config map[string]string) error {
	switch instance.Type {
	case "cowrie":
		return hm.setupCowrie(instance, config)
	case "dionaea":
		return hm.setupDionaea(instance, config)
	case "heralding":
		return hm.setupHeralding(instance, config)
	case "elasticpot":
		return hm.setupElasticpot(instance, config)
	case "mailoney":
		return hm.setupMailoney(instance, config)
	default:
		// Try generic Python honeypot setup
		return hm.setupGenericPython(instance, config)
	}
}

// setupCowrie sets up Cowrie honeypot
func (hm *HoneypotManager) setupCowrie(instance *HoneypotInstance, config map[string]string) error {
	logger.Info("Setting up Cowrie honeypot...")

	// Determine Python command
	pythonCmd := "python3"
	if runtime.GOOS == "windows" {
		pythonCmd = "python"
	}

	// Create virtual environment
	venvPath := filepath.Join(instance.InstallPath, "cowrie-env")
	venvCmd := exec.CommandContext(hm.ctx, pythonCmd, "-m", "venv", venvPath)
	venvCmd.Dir = instance.InstallPath
	if err := venvCmd.Run(); err != nil {
		return fmt.Errorf("failed to create virtualenv: %w", err)
	}

	// Determine pip path
	var pipPath string
	if runtime.GOOS == "windows" {
		pipPath = filepath.Join(venvPath, "Scripts", "pip")
	} else {
		pipPath = filepath.Join(venvPath, "bin", "pip")
	}

	// Upgrade pip
	pipUpgradeCmd := exec.CommandContext(hm.ctx, pipPath, "install", "--upgrade", "pip")
	pipUpgradeCmd.Dir = instance.InstallPath
	if err := pipUpgradeCmd.Run(); err != nil {
		logger.Warnf("Failed to upgrade pip: %v", err)
	}

	// Install requirements
	reqPath := filepath.Join(instance.InstallPath, "requirements.txt")
	if _, err := os.Stat(reqPath); err == nil {
		pipInstallCmd := exec.CommandContext(hm.ctx, pipPath, "install", "-r", reqPath)
		pipInstallCmd.Dir = instance.InstallPath
		pipInstallCmd.Stdout = os.Stdout
		pipInstallCmd.Stderr = os.Stderr
		if err := pipInstallCmd.Run(); err != nil {
			return fmt.Errorf("failed to install requirements: %w", err)
		}
	}

	// Install Cowrie itself
	pipInstallCowrie := exec.CommandContext(hm.ctx, pipPath, "install", "-e", ".")
	pipInstallCowrie.Dir = instance.InstallPath
	if err := pipInstallCowrie.Run(); err != nil {
		logger.Warnf("Failed to install cowrie package: %v (might not be needed)", err)
	}

	// Create configuration
	if err := hm.createCowrieConfig(instance, config); err != nil {
		return fmt.Errorf("failed to create cowrie config: %w", err)
	}

	// Create necessary directories
	dirs := []string{
		filepath.Join(instance.InstallPath, "var", "log", "cowrie"),
		filepath.Join(instance.InstallPath, "var", "lib", "cowrie", "tty"),
		filepath.Join(instance.InstallPath, "var", "lib", "cowrie", "downloads"),
		filepath.Join(instance.InstallPath, "var", "run", "cowrie"),
	}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	return nil
}

// createCowrieConfig creates the Cowrie configuration file
func (hm *HoneypotManager) createCowrieConfig(instance *HoneypotInstance, config map[string]string) error {
	configPath := filepath.Join(instance.InstallPath, "etc", "cowrie.cfg")

	// Ensure etc directory exists
	if err := os.MkdirAll(filepath.Dir(configPath), 0755); err != nil {
		return err
	}

	// Create config content with HoneyBee integration
	configContent := fmt.Sprintf(`# HoneyBee-managed Cowrie Configuration
# Honeypot ID: %s

[honeypot]
hostname = honeybee-%s
log_path = var/log/cowrie
download_path = var/lib/cowrie/downloads
state_path = var/lib/cowrie
data_path = src/cowrie/data
contents_path = honeyfs
backend = shell
logtype = plain
timezone = UTC

[ssh]
enabled = true
listen_endpoints = tcp:%d:interface=0.0.0.0

[telnet]
enabled = true
listen_endpoints = tcp:%d:interface=0.0.0.0

# JSON logging for local storage
[output_jsonlog]
enabled = true
logfile = var/log/cowrie/cowrie.json

# Socket output to HoneyBee Node
[output_socketlog]
enabled = true
address = 127.0.0.1:%d
timeout = 5
`, instance.ID, instance.ID, instance.SSHPort, instance.TelnetPort, hm.listenerPort)

	// Apply custom config overrides
	for key, value := range config {
		configContent += fmt.Sprintf("\n%s = %s", key, value)
	}

	return os.WriteFile(configPath, []byte(configContent), 0644)
}

// setupDionaea sets up Dionaea honeypot
func (hm *HoneypotManager) setupDionaea(instance *HoneypotInstance, config map[string]string) error {
	logger.Info("Setting up Dionaea honeypot...")
	// Dionaea typically requires compilation, this is a simplified setup
	return hm.setupGenericPython(instance, config)
}

// setupHeralding sets up Heralding honeypot
func (hm *HoneypotManager) setupHeralding(instance *HoneypotInstance, config map[string]string) error {
	logger.Info("Setting up Heralding honeypot...")
	return hm.setupGenericPython(instance, config)
}

// setupElasticpot sets up Elasticpot honeypot
func (hm *HoneypotManager) setupElasticpot(instance *HoneypotInstance, config map[string]string) error {
	logger.Info("Setting up Elasticpot honeypot...")
	return hm.setupGenericPython(instance, config)
}

// setupMailoney sets up Mailoney honeypot
func (hm *HoneypotManager) setupMailoney(instance *HoneypotInstance, config map[string]string) error {
	logger.Info("Setting up Mailoney honeypot...")
	return hm.setupGenericPython(instance, config)
}

// setupGenericPython sets up a generic Python-based honeypot
func (hm *HoneypotManager) setupGenericPython(instance *HoneypotInstance, config map[string]string) error {
	logger.Infof("Setting up generic Python honeypot: %s", instance.Type)

	// Determine Python command
	pythonCmd := "python3"
	if runtime.GOOS == "windows" {
		pythonCmd = "python"
	}

	// Create virtual environment
	venvPath := filepath.Join(instance.InstallPath, "venv")
	venvCmd := exec.CommandContext(hm.ctx, pythonCmd, "-m", "venv", venvPath)
	venvCmd.Dir = instance.InstallPath
	if err := venvCmd.Run(); err != nil {
		return fmt.Errorf("failed to create virtualenv: %w", err)
	}

	// Determine pip path
	var pipPath string
	if runtime.GOOS == "windows" {
		pipPath = filepath.Join(venvPath, "Scripts", "pip")
	} else {
		pipPath = filepath.Join(venvPath, "bin", "pip")
	}

	// Upgrade pip
	pipUpgradeCmd := exec.CommandContext(hm.ctx, pipPath, "install", "--upgrade", "pip")
	pipUpgradeCmd.Dir = instance.InstallPath
	pipUpgradeCmd.Run() // Ignore errors

	// Install requirements if exists
	reqPath := filepath.Join(instance.InstallPath, "requirements.txt")
	if _, err := os.Stat(reqPath); err == nil {
		pipInstallCmd := exec.CommandContext(hm.ctx, pipPath, "install", "-r", reqPath)
		pipInstallCmd.Dir = instance.InstallPath
		pipInstallCmd.Stdout = os.Stdout
		pipInstallCmd.Stderr = os.Stderr
		if err := pipInstallCmd.Run(); err != nil {
			return fmt.Errorf("failed to install requirements: %w", err)
		}
	}

	// Create log directory
	logDir := filepath.Join(instance.InstallPath, "logs")
	os.MkdirAll(logDir, 0755)

	return nil
}

// StartHoneypot starts a honeypot instance
func (hm *HoneypotManager) StartHoneypot(honeypotID string) error {
	hm.mu.Lock()
	instance, exists := hm.honeypots[honeypotID]
	hm.mu.Unlock()

	if !exists {
		return fmt.Errorf("honeypot %s not found", honeypotID)
	}

	instance.mu.Lock()
	defer instance.mu.Unlock()

	if instance.Status == protocol.HoneypotStatusRunning {
		return fmt.Errorf("honeypot %s is already running", honeypotID)
	}

	switch instance.Type {
	case "cowrie":
		return hm.startCowrie(instance)
	default:
		// Try generic Python start
		return hm.startGenericPython(instance)
	}
}

// startGenericPython starts a generic Python-based honeypot
func (hm *HoneypotManager) startGenericPython(instance *HoneypotInstance) error {
	logger.Infof("Starting %s honeypot %s", instance.Type, instance.ID)

	// Determine Python path
	var pythonPath string
	if runtime.GOOS == "windows" {
		pythonPath = filepath.Join(instance.InstallPath, "venv", "Scripts", "python")
	} else {
		pythonPath = filepath.Join(instance.InstallPath, "venv", "bin", "python")
	}

	// Create context for the process
	ctx, cancel := context.WithCancel(hm.ctx)
	instance.cancelFunc = cancel

	// Look for common entry points
	entryPoints := []string{"main.py", "run.py", "server.py", "honeypot.py"}
	var entryPoint string
	for _, ep := range entryPoints {
		epPath := filepath.Join(instance.InstallPath, ep)
		if _, err := os.Stat(epPath); err == nil {
			entryPoint = ep
			break
		}
	}

	if entryPoint == "" {
		cancel()
		return fmt.Errorf("no entry point found for %s", instance.Type)
	}

	cmd := exec.CommandContext(ctx, pythonPath, entryPoint)
	cmd.Dir = instance.InstallPath
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		cancel()
		return fmt.Errorf("failed to start %s: %w", instance.Type, err)
	}

	instance.Process = cmd
	instance.Status = protocol.HoneypotStatusRunning
	hm.sendStatusUpdate(instance, fmt.Sprintf("%s honeypot started", instance.Type))

	// Monitor process
	go func() {
		err := cmd.Wait()
		instance.mu.Lock()
		if instance.Status == protocol.HoneypotStatusRunning {
			if err != nil {
				logger.Errorf("%s process exited with error: %v", instance.Type, err)
				instance.Status = protocol.HoneypotStatusFailed
				hm.sendStatusUpdate(instance, fmt.Sprintf("Process exited: %v", err))
			} else {
				instance.Status = protocol.HoneypotStatusStopped
				hm.sendStatusUpdate(instance, "Process exited normally")
			}
		}
		instance.mu.Unlock()
	}()

	return nil
}

// startCowrie starts the Cowrie honeypot
func (hm *HoneypotManager) startCowrie(instance *HoneypotInstance) error {
	logger.Infof("Starting Cowrie honeypot %s", instance.ID)

	// Determine paths
	var pythonPath string
	if runtime.GOOS == "windows" {
		pythonPath = filepath.Join(instance.InstallPath, "cowrie-env", "Scripts", "python")
	} else {
		pythonPath = filepath.Join(instance.InstallPath, "cowrie-env", "bin", "python")
	}

	// Create context for the process
	ctx, cancel := context.WithCancel(hm.ctx)
	instance.cancelFunc = cancel

	// Start Cowrie using twistd
	twistdPath := filepath.Join(filepath.Dir(pythonPath), "twistd")
	cmd := exec.CommandContext(ctx, twistdPath, "-n", "cowrie")
	cmd.Dir = instance.InstallPath
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("PYTHONPATH=%s", filepath.Join(instance.InstallPath, "src")),
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		cancel()
		return fmt.Errorf("failed to start cowrie: %w", err)
	}

	instance.Process = cmd
	instance.Status = protocol.HoneypotStatusRunning
	hm.sendStatusUpdate(instance, "Honeypot started")

	// Monitor process in background
	go func() {
		err := cmd.Wait()
		instance.mu.Lock()
		if instance.Status == protocol.HoneypotStatusRunning {
			if err != nil {
				logger.Errorf("Cowrie process exited with error: %v", err)
				instance.Status = protocol.HoneypotStatusFailed
				hm.sendStatusUpdate(instance, fmt.Sprintf("Process exited: %v", err))
			} else {
				instance.Status = protocol.HoneypotStatusStopped
				hm.sendStatusUpdate(instance, "Process exited normally")
			}
		}
		instance.mu.Unlock()
	}()

	logger.Infof("Cowrie honeypot %s started on SSH:%d, Telnet:%d",
		instance.ID, instance.SSHPort, instance.TelnetPort)

	return nil
}

// StopHoneypot stops a honeypot instance
func (hm *HoneypotManager) StopHoneypot(honeypotID string) error {
	hm.mu.RLock()
	instance, exists := hm.honeypots[honeypotID]
	hm.mu.RUnlock()

	if !exists {
		return fmt.Errorf("honeypot %s not found", honeypotID)
	}

	return hm.stopHoneypot(instance)
}

// stopHoneypot stops a specific honeypot instance
func (hm *HoneypotManager) stopHoneypot(instance *HoneypotInstance) error {
	instance.mu.Lock()
	defer instance.mu.Unlock()

	if instance.Status != protocol.HoneypotStatusRunning {
		return nil
	}

	logger.Infof("Stopping honeypot %s", instance.ID)

	if instance.cancelFunc != nil {
		instance.cancelFunc()
	}

	if instance.Process != nil && instance.Process.Process != nil {
		instance.Process.Process.Kill()
	}

	instance.Status = protocol.HoneypotStatusStopped
	hm.sendStatusUpdate(instance, "Honeypot stopped")

	return nil
}

// GetStatus returns the status of a honeypot
func (hm *HoneypotManager) GetStatus(honeypotID string) (*protocol.HoneypotStatusUpdate, error) {
	hm.mu.RLock()
	instance, exists := hm.honeypots[honeypotID]
	hm.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("honeypot %s not found", honeypotID)
	}

	return &protocol.HoneypotStatusUpdate{
		NodeID:       hm.nodeID,
		HoneypotID:   instance.ID,
		HoneypotType: instance.Type,
		Status:       instance.Status,
		SSHPort:      instance.SSHPort,
		TelnetPort:   instance.TelnetPort,
	}, nil
}

// ListHoneypots returns all honeypot instances
func (hm *HoneypotManager) ListHoneypots() []*protocol.HoneypotStatusUpdate {
	hm.mu.RLock()
	defer hm.mu.RUnlock()

	var result []*protocol.HoneypotStatusUpdate
	for _, instance := range hm.honeypots {
		result = append(result, &protocol.HoneypotStatusUpdate{
			NodeID:       hm.nodeID,
			HoneypotID:   instance.ID,
			HoneypotType: instance.Type,
			Status:       instance.Status,
			SSHPort:      instance.SSHPort,
			TelnetPort:   instance.TelnetPort,
		})
	}
	return result
}

// sendStatusUpdate sends a honeypot status update to the event channel
func (hm *HoneypotManager) sendStatusUpdate(instance *HoneypotInstance, message string) {
	update := &protocol.HoneypotStatusUpdate{
		NodeID:       hm.nodeID,
		HoneypotID:   instance.ID,
		HoneypotType: instance.Type,
		Status:       instance.Status,
		Message:      message,
		SSHPort:      instance.SSHPort,
		TelnetPort:   instance.TelnetPort,
	}

	// Create a HoneypotEvent to carry the status update
	event := &protocol.HoneypotEvent{
		NodeID:       hm.nodeID,
		HoneypotID:   instance.ID,
		HoneypotType: instance.Type,
		EventID:      "honeybee.honeypot.status",
		Timestamp:    time.Now(),
		Message:      fmt.Sprintf("Status: %s - %s", update.Status, message),
	}

	select {
	case hm.eventChan <- event:
	default:
		logger.Warn("Event channel full, dropping status update")
	}
}

// startEventListener starts a TCP listener for receiving honeypot events
func (hm *HoneypotManager) startEventListener() error {
	// Find an available port starting from 9100
	var listener net.Listener
	var err error
	for port := 9100; port < 9200; port++ {
		listener, err = net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil {
			hm.listenerPort = port
			break
		}
	}
	if listener == nil {
		return fmt.Errorf("failed to find available port for event listener: %w", err)
	}

	hm.eventListener = listener

	// Start accepting connections
	go hm.acceptConnections()

	return nil
}

// acceptConnections accepts incoming connections from honeypots
func (hm *HoneypotManager) acceptConnections() {
	for {
		conn, err := hm.eventListener.Accept()
		if err != nil {
			select {
			case <-hm.ctx.Done():
				return
			default:
				logger.Errorf("Failed to accept connection: %v", err)
				continue
			}
		}
		go hm.handleConnection(conn)
	}
}

// handleConnection handles a single honeypot connection
func (hm *HoneypotManager) handleConnection(conn net.Conn) {
	defer conn.Close()

	reader := bufio.NewReader(conn)
	for {
		select {
		case <-hm.ctx.Done():
			return
		default:
		}

		line, err := reader.ReadBytes('\n')
		if err != nil {
			return
		}

		// Parse the JSON event from Cowrie
		var rawEvent map[string]interface{}
		if err := json.Unmarshal(line, &rawEvent); err != nil {
			logger.Warnf("Failed to parse honeypot event: %v", err)
			continue
		}

		// Find the honeypot instance this event belongs to
		honeypotID := hm.findHoneypotForEvent(rawEvent)

		// Create HoneypotEvent
		event := protocol.NewHoneypotEvent(hm.nodeID, honeypotID, "cowrie", rawEvent)

		// Send to event channel
		select {
		case hm.eventChan <- event:
		default:
			logger.Warn("Event channel full, dropping honeypot event")
		}
	}
}

// findHoneypotForEvent tries to determine which honeypot an event belongs to
func (hm *HoneypotManager) findHoneypotForEvent(event map[string]interface{}) string {
	// Try to get sensor name from event
	if sensor, ok := event["sensor"].(string); ok {
		return sensor
	}

	// Default to first honeypot if only one exists
	hm.mu.RLock()
	defer hm.mu.RUnlock()

	for id := range hm.honeypots {
		return id
	}

	return "unknown"
}
