// Package protocol defines the communication protocol between HoneyBee nodes
// and the HoneyBee Core manager. It provides message types, envelopes, and
// serialization formats for all inter-component communication.
//
// The protocol uses JSON encoding wrapped in versioned envelopes to support
// backwards compatibility and protocol evolution.
package protocol

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/honeybee/node/internal/constants"
	"github.com/honeybee/node/internal/errors"
)

// NodeType classifies the capability level of a node
type NodeType string

const (
	NodeTypeFull  NodeType = "Full"
	NodeTypeAgent NodeType = "Agent"
)

// NodeStatus represents the lifecycle state of a node
type NodeStatus string

const (
	NodeStatusDeploying NodeStatus = "Deploying"
	NodeStatusRunning   NodeStatus = "Running"
	NodeStatusStopped   NodeStatus = "Stopped"
	NodeStatusFailed    NodeStatus = "Failed"
	NodeStatusUnknown   NodeStatus = "Unknown"
)

// HoneypotStatus represents the lifecycle state of a honeypot
type HoneypotStatus string

const (
	HoneypotStatusInstalling HoneypotStatus = "Installing"
	HoneypotStatusRunning    HoneypotStatus = "Running"
	HoneypotStatusStopped    HoneypotStatus = "Stopped"
	HoneypotStatusFailed     HoneypotStatus = "Failed"
)

// MessageEnvelope wraps all protocol messages with versioning
type MessageEnvelope struct {
	Version uint64      `json:"version"`
	Message MessageType `json:"message"`
}

// MessageType represents the union of all message types
type MessageType struct {
	// Node to Manager messages
	NodeRegistration *NodeRegistration `json:"NodeRegistration,omitempty"`
	NodeStatusUpdate *NodeStatusUpdate `json:"NodeStatusUpdate,omitempty"`
	NodeEvent        *NodeEvent        `json:"NodeEvent,omitempty"`
	NodeDrop         *bool             `json:"NodeDrop,omitempty"` // Use pointer to detect presence

	// Honeypot-specific messages (Node → Manager)
	HoneypotStatusUpdate *HoneypotStatusUpdate `json:"HoneypotStatusUpdate,omitempty"`
	HoneypotEvent        *HoneypotEvent        `json:"HoneypotEvent,omitempty"`

	// Manager to Node messages
	NodeCommand     *NodeCommand     `json:"NodeCommand,omitempty"`
	RegistrationAck *RegistrationAck `json:"RegistrationAck,omitempty"`

	// Honeypot commands (Manager → Node)
	InstallHoneypot *InstallHoneypotCmd `json:"InstallHoneypot,omitempty"`
	StartHoneypot   *StartHoneypotCmd   `json:"StartHoneypot,omitempty"`
	StopHoneypot    *StopHoneypotCmd    `json:"StopHoneypot,omitempty"`
}

// NodeRegistration is sent during initial connection handshake
type NodeRegistration struct {
	NodeID   uint64   `json:"node_id"`
	NodeName string   `json:"node_name"`
	Address  string   `json:"address"`
	Port     uint16   `json:"port"`
	NodeType NodeType `json:"node_type"`
	TOTPCode string   `json:"totp_code,omitempty"` // TOTP for authentication
}

// NodeStatusUpdate publishes the current operating state
type NodeStatusUpdate struct {
	NodeID uint64     `json:"node_id"`
	Status NodeStatus `json:"status"`
}

// NodeEvent represents noteworthy events
type NodeEvent struct {
	Type        string `json:"type"` // "Started", "Stopped", "Alarm", "Error"
	Message     string `json:"message,omitempty"`
	Description string `json:"description,omitempty"`
}

// NodeCommand instructs a node to perform an action
type NodeCommand struct {
	NodeID  uint64 `json:"node_id"`
	Command string `json:"command"`
}

// RegistrationAck confirms whether registration succeeded
type RegistrationAck struct {
	NodeID   uint64  `json:"node_id"`
	Accepted bool    `json:"accepted"`
	Message  *string `json:"message,omitempty"`
	TOTPKey  string  `json:"totp_key,omitempty"` // Sent on first registration
}

// =============================================================================
// Honeypot-specific Protocol Messages
// =============================================================================

// InstallHoneypotCmd instructs the node to install a honeypot from a Git repository
type InstallHoneypotCmd struct {
	HoneypotID   string            `json:"honeypot_id"`           // Unique ID for this honeypot instance
	HoneypotType string            `json:"honeypot_type"`         // "cowrie", "dionaea", etc.
	GitURL       string            `json:"git_url"`               // GitHub URL to clone
	GitBranch    string            `json:"git_branch,omitempty"`  // Branch to checkout (default: main)
	Config       map[string]string `json:"config,omitempty"`      // Configuration overrides
	SSHPort      uint16            `json:"ssh_port,omitempty"`    // SSH honeypot port (default: 2222)
	TelnetPort   uint16            `json:"telnet_port,omitempty"` // Telnet honeypot port (default: 2223)
	AutoStart    bool              `json:"auto_start,omitempty"`  // Start after installation
}

// StartHoneypotCmd instructs the node to start a honeypot
type StartHoneypotCmd struct {
	HoneypotID string `json:"honeypot_id"`
}

// StopHoneypotCmd instructs the node to stop a honeypot
type StopHoneypotCmd struct {
	HoneypotID string `json:"honeypot_id"`
}

// HoneypotStatusUpdate reports the current state of a honeypot
type HoneypotStatusUpdate struct {
	NodeID       uint64         `json:"node_id"`
	HoneypotID   string         `json:"honeypot_id"`
	HoneypotType string         `json:"honeypot_type"`
	Status       HoneypotStatus `json:"status"`
	Message      string         `json:"message,omitempty"`
	SSHPort      uint16         `json:"ssh_port,omitempty"`
	TelnetPort   uint16         `json:"telnet_port,omitempty"`
}

// HoneypotEvent represents events captured by the honeypot (attacks, sessions, etc.)
type HoneypotEvent struct {
	NodeID       uint64                 `json:"node_id"`
	HoneypotID   string                 `json:"honeypot_id"`
	HoneypotType string                 `json:"honeypot_type"`
	EventID      string                 `json:"eventid"` // Cowrie event ID (e.g., "cowrie.login.success")
	Timestamp    time.Time              `json:"timestamp"`
	SessionID    string                 `json:"session,omitempty"`   // Session identifier
	SrcIP        string                 `json:"src_ip,omitempty"`    // Attacker's IP
	SrcPort      uint16                 `json:"src_port,omitempty"`  // Attacker's port
	DstIP        string                 `json:"dst_ip,omitempty"`    // Honeypot IP
	DstPort      uint16                 `json:"dst_port,omitempty"`  // Honeypot port
	Protocol     string                 `json:"protocol,omitempty"`  // "ssh" or "telnet"
	Username     string                 `json:"username,omitempty"`  // Login attempt username
	Password     string                 `json:"password,omitempty"`  // Login attempt password
	Input        string                 `json:"input,omitempty"`     // Command input
	Message      string                 `json:"message,omitempty"`   // Event message
	Success      *bool                  `json:"success,omitempty"`   // Login success/failure
	RawEvent     map[string]interface{} `json:"raw_event,omitempty"` // Full raw event from honeypot
}

// =============================================================================
// Validation Methods
// =============================================================================

// Validate checks if a NodeRegistration is valid
func (nr *NodeRegistration) Validate() error {
	if nr.NodeID == 0 {
		return errors.Wrap(nil, errors.ErrCategoryProtocol, "INVALID_NODE_ID", "Node ID cannot be zero")
	}
	if nr.NodeName == "" {
		return errors.Wrap(nil, errors.ErrCategoryProtocol, "INVALID_NODE_NAME", "Node name cannot be empty")
	}
	if nr.NodeType != NodeTypeFull && nr.NodeType != NodeTypeAgent {
		return errors.Wrap(nil, errors.ErrCategoryProtocol, "INVALID_NODE_TYPE", "Invalid node type")
	}
	return nil
}

// Validate checks if an InstallHoneypotCmd is valid
func (cmd *InstallHoneypotCmd) Validate() error {
	if cmd.HoneypotID == "" {
		return errors.Wrap(nil, errors.ErrCategoryProtocol, "INVALID_HONEYPOT_ID", "Honeypot ID cannot be empty")
	}
	if cmd.HoneypotType == "" {
		return errors.Wrap(nil, errors.ErrCategoryProtocol, "INVALID_HONEYPOT_TYPE", "Honeypot type cannot be empty")
	}
	// Validate honeypot type is supported
	supported := false
	for _, t := range constants.SupportedHoneypotTypes {
		if cmd.HoneypotType == t {
			supported = true
			break
		}
	}
	if !supported {
		return errors.Wrap(nil, errors.ErrCategoryProtocol, "UNSUPPORTED_HONEYPOT",
			fmt.Sprintf("Honeypot type '%s' is not supported", cmd.HoneypotType))
	}
	return nil
}

// Validate checks if a StartHoneypotCmd is valid
func (cmd *StartHoneypotCmd) Validate() error {
	if cmd.HoneypotID == "" {
		return errors.Wrap(nil, errors.ErrCategoryProtocol, "INVALID_HONEYPOT_ID", "Honeypot ID cannot be empty")
	}
	return nil
}

// Validate checks if a StopHoneypotCmd is valid
func (cmd *StopHoneypotCmd) Validate() error {
	if cmd.HoneypotID == "" {
		return errors.Wrap(nil, errors.ErrCategoryProtocol, "INVALID_HONEYPOT_ID", "Honeypot ID cannot be empty")
	}
	return nil
}

// Validate checks if a MessageEnvelope is valid
func (env *MessageEnvelope) Validate() error {
	if env.Version != constants.ProtocolVersion {
		return errors.Wrap(nil, errors.ErrCategoryProtocol, "VERSION_MISMATCH",
			fmt.Sprintf("Protocol version mismatch: expected %d, got %d",
				constants.ProtocolVersion, env.Version))
	}
	return nil
}

// =============================================================================
// Encoding/Decoding Methods
// =============================================================================

// MarshalEnvelope wraps a message in an envelope and marshals to JSON
func MarshalEnvelope(msg *MessageType) ([]byte, error) {
	envelope := &MessageEnvelope{
		Version: constants.ProtocolVersion,
		Message: *msg,
	}

	data, err := json.Marshal(envelope)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCategoryProtocol, "MARSHAL_FAILED", "Failed to marshal message")
	}

	if len(data) > constants.MaxMessageSize {
		return nil, errors.Wrap(nil, errors.ErrCategoryProtocol, "MESSAGE_TOO_LARGE",
			fmt.Sprintf("Message size %d exceeds maximum %d", len(data), constants.MaxMessageSize))
	}

	return data, nil
}

// UnmarshalEnvelope unmarshals JSON data into a MessageEnvelope
func UnmarshalEnvelope(data []byte) (*MessageEnvelope, error) {
	if len(data) > constants.MaxMessageSize {
		return nil, errors.Wrap(nil, errors.ErrCategoryProtocol, "MESSAGE_TOO_LARGE",
			fmt.Sprintf("Message size %d exceeds maximum %d", len(data), constants.MaxMessageSize))
	}

	var envelope MessageEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return nil, errors.Wrap(err, errors.ErrCategoryProtocol, "UNMARSHAL_FAILED", "Failed to unmarshal message")
	}

	if err := envelope.Validate(); err != nil {
		return nil, err
	}

	return &envelope, nil
}

// =============================================================================
// Helper Constructors
// =============================================================================

// NewStartedEvent creates a new "Started" node event
func NewStartedEvent() *NodeEvent {
	return &NodeEvent{Type: "Started"}
}

// NewStoppedEvent creates a new "Stopped" node event
func NewStoppedEvent() *NodeEvent {
	return &NodeEvent{Type: "Stopped"}
}

// NewAlarmEvent creates a new "Alarm" node event with a description
func NewAlarmEvent(description string) *NodeEvent {
	return &NodeEvent{
		Type:        "Alarm",
		Description: description,
	}
}

// NewErrorEvent creates a new "Error" node event with a message
func NewErrorEvent(message string) *NodeEvent {
	return &NodeEvent{
		Type:    "Error",
		Message: message,
	}
}

// NewHoneypotEvent creates a new honeypot event from raw Cowrie JSON
func NewHoneypotEvent(nodeID uint64, honeypotID, honeypotType string, rawEvent map[string]interface{}) *HoneypotEvent {
	event := &HoneypotEvent{
		NodeID:       nodeID,
		HoneypotID:   honeypotID,
		HoneypotType: honeypotType,
		Timestamp:    time.Now(),
		RawEvent:     rawEvent,
	}

	// Extract common fields from Cowrie event
	if eventID, ok := rawEvent["eventid"].(string); ok {
		event.EventID = eventID
	}
	if session, ok := rawEvent["session"].(string); ok {
		event.SessionID = session
	}
	if srcIP, ok := rawEvent["src_ip"].(string); ok {
		event.SrcIP = srcIP
	}
	if srcPort, ok := rawEvent["src_port"].(float64); ok {
		event.SrcPort = uint16(srcPort)
	}
	if dstIP, ok := rawEvent["dst_ip"].(string); ok {
		event.DstIP = dstIP
	}
	if dstPort, ok := rawEvent["dst_port"].(float64); ok {
		event.DstPort = uint16(dstPort)
	}
	if protocol, ok := rawEvent["protocol"].(string); ok {
		event.Protocol = protocol
	}
	if username, ok := rawEvent["username"].(string); ok {
		event.Username = username
	}
	if password, ok := rawEvent["password"].(string); ok {
		event.Password = password
	}
	if input, ok := rawEvent["input"].(string); ok {
		event.Input = input
	}
	if message, ok := rawEvent["message"].(string); ok {
		event.Message = message
	}
	if success, ok := rawEvent["success"].(bool); ok {
		event.Success = &success
	}

	return event
}
