package client

import (
	"bufio"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/honeybee/node/internal/auth"
	"github.com/honeybee/node/internal/config"
	"github.com/honeybee/node/internal/honeypot"
	"github.com/honeybee/node/internal/logger"
	"github.com/honeybee/node/internal/protocol"
)

// NodeClient manages the connection to the honeybee_core manager
type NodeClient struct {
	cfg            *config.Config
	nodeID         uint64
	totpMgr        *auth.TOTPManager
	tlsConfig      *tls.Config
	conn           net.Conn
	writer         *bufio.Writer
	reader         *bufio.Reader
	mu             sync.Mutex
	stopChan       chan struct{}
	doneChan       chan struct{}
	registered     bool
	honeypotMgr    *honeypot.HoneypotManager
}

// NewNodeClient creates a new node client
func NewNodeClient(cfg *config.Config) (*NodeClient, error) {
	// Generate random node ID
	nodeID, err := generateNodeID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate node ID: %w", err)
	}

	// Initialize TOTP manager if enabled
	var totpMgr *auth.TOTPManager
	if cfg.Auth.TOTPEnabled {
		totpMgr, err = auth.NewTOTPManager(cfg.Auth.TOTPSecretDir)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize TOTP manager: %w", err)
		}
	}

	// Initialize TLS config if enabled
	var tlsConfig *tls.Config
	if cfg.TLS.Enabled {
		tlsCfg := &auth.TLSConfig{
			CertFile:           cfg.TLS.CertFile,
			KeyFile:            cfg.TLS.KeyFile,
			CAFile:             cfg.TLS.CAFile,
			InsecureSkipVerify: cfg.TLS.InsecureSkipVerify,
			ServerName:         cfg.TLS.ServerName,
		}
		tlsConfig, err = auth.LoadTLSConfig(tlsCfg)
		if err != nil {
			return nil, fmt.Errorf("failed to load TLS config: %w", err)
		}
	}

	// Initialize honeypot manager if enabled
	var honeypotMgr *honeypot.HoneypotManager
	if cfg.Honeypot.Enabled {
		honeypotMgr, err = honeypot.NewHoneypotManager(cfg.Honeypot.BaseDir, nodeID)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize honeypot manager: %w", err)
		}
	}

	return &NodeClient{
		cfg:         cfg,
		nodeID:      nodeID,
		totpMgr:     totpMgr,
		tlsConfig:   tlsConfig,
		stopChan:    make(chan struct{}),
		doneChan:    make(chan struct{}),
		honeypotMgr: honeypotMgr,
	}, nil
}

// Run starts the node client main loop
func (nc *NodeClient) Run() error {
	defer close(nc.doneChan)

	logger.WithFields(map[string]interface{}{
		"node_id":   nc.nodeID,
		"node_name": nc.cfg.Node.Name,
		"node_type": nc.cfg.Node.Type,
	}).Info("Starting node client")

	// Start honeypot manager if enabled
	if nc.honeypotMgr != nil {
		if err := nc.honeypotMgr.Start(); err != nil {
			logger.Errorf("Failed to start honeypot manager: %v", err)
		} else {
			logger.Info("Honeypot manager started")
		}
	}

	for {
		select {
		case <-nc.stopChan:
			logger.Info("Node client shutting down")
			if nc.honeypotMgr != nil {
				nc.honeypotMgr.Stop()
			}
			return nil
		default:
		}

		// Connect to server
		if err := nc.connect(); err != nil {
			logger.Errorf("Connection failed: %v", err)
			nc.waitReconnect()
			continue
		}

		// Register with server
		if err := nc.register(); err != nil {
			logger.Errorf("Registration failed: %v", err)
			nc.closeConnection()
			nc.waitReconnect()
			continue
		}

		// Send initial status
		if err := nc.sendStatusUpdate(protocol.NodeStatusRunning); err != nil {
			logger.Errorf("Failed to send initial status: %v", err)
			nc.closeConnection()
			nc.waitReconnect()
			continue
		}

		// Run main event loop
		if err := nc.eventLoop(); err != nil {
			logger.Errorf("Event loop error: %v", err)
		}

		nc.closeConnection()
		nc.waitReconnect()
	}
}

// connect establishes connection to the server
func (nc *NodeClient) connect() error {
	timeout := time.Duration(nc.cfg.Server.ConnectionTimeout) * time.Second
	logger.Infof("Connecting to server at %s (TLS: %v)", nc.cfg.Server.Address, nc.cfg.TLS.Enabled)

	var conn net.Conn
	var err error

	if nc.cfg.TLS.Enabled {
		dialer := &net.Dialer{Timeout: timeout}
		conn, err = tls.DialWithDialer(dialer, "tcp", nc.cfg.Server.Address, nc.tlsConfig)
		if err != nil {
			return fmt.Errorf("TLS connection failed: %w", err)
		}

		// Verify TLS connection
		tlsConn := conn.(*tls.Conn)
		if err := tlsConn.Handshake(); err != nil {
			conn.Close()
			return fmt.Errorf("TLS handshake failed: %w", err)
		}

		state := tlsConn.ConnectionState()
		logger.Debugf("TLS connection established: version=%s, cipher=%s",
			tlsVersionString(state.Version),
			tls.CipherSuiteName(state.CipherSuite))
	} else {
		conn, err = net.DialTimeout("tcp", nc.cfg.Server.Address, timeout)
		if err != nil {
			return fmt.Errorf("TCP connection failed: %w", err)
		}
		logger.Warn("Connected without TLS encryption (not recommended for production)")
	}

	nc.conn = conn
	nc.writer = bufio.NewWriter(conn)
	nc.reader = bufio.NewReader(conn)

	logger.Info("Connected to server successfully")
	return nil
}

// register sends registration message to the server
func (nc *NodeClient) register() error {
	logger.Info("Sending registration")

	registration := protocol.NodeRegistration{
		NodeID:   nc.nodeID,
		NodeName: nc.cfg.Node.Name,
		Address:  nc.cfg.Node.Address,
		Port:     nc.cfg.Node.Port,
		NodeType: protocol.NodeType(nc.cfg.Node.Type),
	}

	// Add TOTP code if enabled
	if nc.cfg.Auth.TOTPEnabled && nc.totpMgr != nil {
		// Load or generate TOTP secret
		_, isNew, err := nc.totpMgr.LoadOrGenerateSecret()
		if err != nil {
			return fmt.Errorf("failed to load TOTP secret: %w", err)
		}

		if isNew {
			logger.Info("Generated new TOTP secret (first-time registration)")
		} else {
			logger.Debug("Using existing TOTP secret")
		}

		// Generate TOTP code
		code, err := nc.totpMgr.GenerateCode()
		if err != nil {
			return fmt.Errorf("failed to generate TOTP code: %w", err)
		}

		registration.TOTPCode = code
		logger.Debugf("TOTP code generated: %s", code)
	}

	envelope := protocol.MessageEnvelope{
		Version: protocol.ProtocolVersion,
		Message: protocol.MessageType{
			NodeRegistration: &registration,
		},
	}

	if err := nc.sendMessage(envelope); err != nil {
		return fmt.Errorf("failed to send registration: %w", err)
	}

	// Wait for registration acknowledgment
	ack, err := nc.waitForRegistrationAck()
	if err != nil {
		return fmt.Errorf("registration acknowledgment failed: %w", err)
	}

	if !ack.Accepted {
		msg := "unknown reason"
		if ack.Message != nil {
			msg = *ack.Message
		}
		return fmt.Errorf("registration rejected: %s", msg)
	}

	logger.Info("Registration accepted")
	if ack.Message != nil {
		logger.Infof("Server message: %s", *ack.Message)
	}

	// If server provides TOTP key (first registration), save it
	if ack.TOTPKey != "" && nc.totpMgr != nil {
		logger.Info("Received TOTP key from server, saving...")
		if err := nc.totpMgr.SetSecret(ack.TOTPKey); err != nil {
			logger.Errorf("Failed to save TOTP key: %v", err)
		}
	}

	nc.registered = true
	return nil
}

// waitForRegistrationAck waits for registration acknowledgment
func (nc *NodeClient) waitForRegistrationAck() (*protocol.RegistrationAck, error) {
	// Set read deadline
	nc.conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	defer nc.conn.SetReadDeadline(time.Time{})

	line, err := nc.reader.ReadBytes('\n')
	if err != nil {
		return nil, fmt.Errorf("failed to read acknowledgment: %w", err)
	}

	var envelope protocol.MessageEnvelope
	if err := json.Unmarshal(line, &envelope); err != nil {
		return nil, fmt.Errorf("failed to parse acknowledgment: %w", err)
	}

	// Validate protocol version
	if envelope.Version != protocol.ProtocolVersion {
		logger.Warnf("Protocol version mismatch: got %d, expected %d",
			envelope.Version, protocol.ProtocolVersion)
	}

	if envelope.Message.RegistrationAck == nil {
		return nil, fmt.Errorf("expected RegistrationAck, got different message")
	}

	return envelope.Message.RegistrationAck, nil
}

// eventLoop runs the main event loop
func (nc *NodeClient) eventLoop() error {
	heartbeatTicker := time.NewTicker(time.Duration(nc.cfg.Server.HeartbeatInterval) * time.Second)
	defer heartbeatTicker.Stop()

	errorChan := make(chan error, 2)

	// Start message reader
	go nc.readMessages(errorChan)

	// Get honeypot event channel if available
	var honeypotEvents <-chan *protocol.HoneypotEvent
	if nc.honeypotMgr != nil {
		honeypotEvents = nc.honeypotMgr.EventChannel()
	}

	// Main loop
	for {
		select {
		case <-nc.stopChan:
			nc.sendNodeDrop()
			return nil

		case <-heartbeatTicker.C:
			if err := nc.sendStatusUpdate(protocol.NodeStatusRunning); err != nil {
				return fmt.Errorf("heartbeat failed: %w", err)
			}
			logger.Debug("Heartbeat sent")

		case event, ok := <-honeypotEvents:
			if ok && event != nil {
				if err := nc.sendHoneypotEvent(event); err != nil {
					logger.Errorf("Failed to send honeypot event: %v", err)
				}
			}

		case err := <-errorChan:
			return err
		}
	}
}

// readMessages reads messages from the server
func (nc *NodeClient) readMessages(errorChan chan<- error) {
	for {
		line, err := nc.reader.ReadBytes('\n')
		if err != nil {
			errorChan <- fmt.Errorf("read error: %w", err)
			return
		}

		var envelope protocol.MessageEnvelope
		if err := json.Unmarshal(line, &envelope); err != nil {
			logger.Warnf("Failed to parse message: %v", err)
			continue
		}

		if err := nc.handleMessage(&envelope); err != nil {
			logger.Errorf("Failed to handle message: %v", err)
		}
	}
}

// handleMessage processes incoming messages from the server
func (nc *NodeClient) handleMessage(envelope *protocol.MessageEnvelope) error {
	// Validate protocol version
	if envelope.Version != protocol.ProtocolVersion {
		logger.Warnf("Protocol version mismatch: got %d, expected %d",
			envelope.Version, protocol.ProtocolVersion)
	}

	// Handle NodeCommand
	if cmd := envelope.Message.NodeCommand; cmd != nil {
		logger.Infof("Received command: %s", cmd.Command)

		switch cmd.Command {
		case "stop":
			nc.sendStatusUpdate(protocol.NodeStatusStopped)
			nc.sendEvent(protocol.NewStoppedEvent())
			go func() {
				time.Sleep(100 * time.Millisecond)
				nc.Stop()
			}()

		case "status":
			nc.sendStatusUpdate(protocol.NodeStatusRunning)

		case "restart":
			logger.Info("Restart command received")
			nc.sendStatusUpdate(protocol.NodeStatusStopped)
			time.Sleep(500 * time.Millisecond)
			nc.sendStatusUpdate(protocol.NodeStatusRunning)
			nc.sendEvent(protocol.NewStartedEvent())

		default:
			logger.Warnf("Unknown command: %s", cmd.Command)
			nc.sendEvent(protocol.NewErrorEvent(fmt.Sprintf("Unknown command: %s", cmd.Command)))
		}
	}

	// Handle InstallHoneypot command
	if cmd := envelope.Message.InstallHoneypot; cmd != nil {
		logger.Infof("Received InstallHoneypot command: %s from %s", cmd.HoneypotID, cmd.GitURL)
		nc.handleInstallHoneypot(cmd)
	}

	// Handle StartHoneypot command
	if cmd := envelope.Message.StartHoneypot; cmd != nil {
		logger.Infof("Received StartHoneypot command: %s", cmd.HoneypotID)
		nc.handleStartHoneypot(cmd)
	}

	// Handle StopHoneypot command
	if cmd := envelope.Message.StopHoneypot; cmd != nil {
		logger.Infof("Received StopHoneypot command: %s", cmd.HoneypotID)
		nc.handleStopHoneypot(cmd)
	}

	return nil
}

// handleInstallHoneypot handles the InstallHoneypot command
func (nc *NodeClient) handleInstallHoneypot(cmd *protocol.InstallHoneypotCmd) {
	if nc.honeypotMgr == nil {
		logger.Error("Honeypot manager not enabled")
		nc.sendEvent(protocol.NewErrorEvent("Honeypot manager not enabled"))
		return
	}

	// Set default ports from config if not specified
	if cmd.SSHPort == 0 {
		cmd.SSHPort = nc.cfg.Honeypot.DefaultSSH
	}
	if cmd.TelnetPort == 0 {
		cmd.TelnetPort = nc.cfg.Honeypot.DefaultTel
	}

	if err := nc.honeypotMgr.InstallHoneypot(cmd); err != nil {
		logger.Errorf("Failed to install honeypot: %v", err)
		nc.sendEvent(protocol.NewErrorEvent(fmt.Sprintf("Failed to install honeypot: %v", err)))
	}
}

// handleStartHoneypot handles the StartHoneypot command
func (nc *NodeClient) handleStartHoneypot(cmd *protocol.StartHoneypotCmd) {
	if nc.honeypotMgr == nil {
		logger.Error("Honeypot manager not enabled")
		nc.sendEvent(protocol.NewErrorEvent("Honeypot manager not enabled"))
		return
	}

	if err := nc.honeypotMgr.StartHoneypot(cmd.HoneypotID); err != nil {
		logger.Errorf("Failed to start honeypot: %v", err)
		nc.sendEvent(protocol.NewErrorEvent(fmt.Sprintf("Failed to start honeypot: %v", err)))
	}
}

// handleStopHoneypot handles the StopHoneypot command
func (nc *NodeClient) handleStopHoneypot(cmd *protocol.StopHoneypotCmd) {
	if nc.honeypotMgr == nil {
		logger.Error("Honeypot manager not enabled")
		nc.sendEvent(protocol.NewErrorEvent("Honeypot manager not enabled"))
		return
	}

	if err := nc.honeypotMgr.StopHoneypot(cmd.HoneypotID); err != nil {
		logger.Errorf("Failed to stop honeypot: %v", err)
		nc.sendEvent(protocol.NewErrorEvent(fmt.Sprintf("Failed to stop honeypot: %v", err)))
	}
}

// sendHoneypotEvent sends a honeypot event to the server
func (nc *NodeClient) sendHoneypotEvent(event *protocol.HoneypotEvent) error {
	envelope := protocol.MessageEnvelope{
		Version: protocol.ProtocolVersion,
		Message: protocol.MessageType{
			HoneypotEvent: event,
		},
	}

	return nc.sendMessage(envelope)
}

// sendMessage sends a message to the server
func (nc *NodeClient) sendMessage(envelope protocol.MessageEnvelope) error {
	nc.mu.Lock()
	defer nc.mu.Unlock()

	data, err := json.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	// Write message with newline
	if _, err := nc.writer.Write(data); err != nil {
		return fmt.Errorf("failed to write message: %w", err)
	}

	if err := nc.writer.WriteByte('\n'); err != nil {
		return fmt.Errorf("failed to write newline: %w", err)
	}

	if err := nc.writer.Flush(); err != nil {
		return fmt.Errorf("failed to flush: %w", err)
	}

	return nil
}

// sendStatusUpdate sends a status update to the server
func (nc *NodeClient) sendStatusUpdate(status protocol.NodeStatus) error {
	envelope := protocol.MessageEnvelope{
		Version: protocol.ProtocolVersion,
		Message: protocol.MessageType{
			NodeStatusUpdate: &protocol.NodeStatusUpdate{
				NodeID: nc.nodeID,
				Status: status,
			},
		},
	}

	return nc.sendMessage(envelope)
}

// sendEvent sends an event to the server
func (nc *NodeClient) sendEvent(event *protocol.NodeEvent) error {
	envelope := protocol.MessageEnvelope{
		Version: protocol.ProtocolVersion,
		Message: protocol.MessageType{
			NodeEvent: event,
		},
	}

	return nc.sendMessage(envelope)
}

// sendNodeDrop sends a node drop message
func (nc *NodeClient) sendNodeDrop() error {
	logger.Info("Sending NodeDrop")

	dropFlag := true
	envelope := protocol.MessageEnvelope{
		Version: protocol.ProtocolVersion,
		Message: protocol.MessageType{
			NodeDrop: &dropFlag,
		},
	}

	return nc.sendMessage(envelope)
}

// closeConnection closes the connection
func (nc *NodeClient) closeConnection() {
	if nc.conn != nil {
		nc.conn.Close()
		nc.conn = nil
	}
	nc.registered = false
}

// waitReconnect waits before reconnecting
func (nc *NodeClient) waitReconnect() {
	delay := time.Duration(nc.cfg.Server.ReconnectDelay) * time.Second
	logger.Infof("Reconnecting in %v...", delay)

	select {
	case <-nc.stopChan:
	case <-time.After(delay):
	}
}

// Stop stops the node client
func (nc *NodeClient) Stop() {
	close(nc.stopChan)
	<-nc.doneChan
}

// generateNodeID generates a random node ID
func generateNodeID() (uint64, error) {
	var id uint64
	err := binary.Read(rand.Reader, binary.BigEndian, &id)
	if err != nil {
		return 0, err
	}
	return id, nil
}

// tlsVersionString returns a string representation of TLS version
func tlsVersionString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("unknown (0x%04x)", version)
	}
}
