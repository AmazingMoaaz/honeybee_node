package protocol

// Protocol version - must match honeybee_core
const ProtocolVersion uint64 = 2

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

	// Manager to Node messages
	NodeCommand     *NodeCommand     `json:"NodeCommand,omitempty"`
	RegistrationAck *RegistrationAck `json:"RegistrationAck,omitempty"`
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

// Helper constructors for events
func NewStartedEvent() *NodeEvent {
	return &NodeEvent{Type: "Started"}
}

func NewStoppedEvent() *NodeEvent {
	return &NodeEvent{Type: "Stopped"}
}

func NewAlarmEvent(description string) *NodeEvent {
	return &NodeEvent{
		Type:        "Alarm",
		Description: description,
	}
}

func NewErrorEvent(message string) *NodeEvent {
	return &NodeEvent{
		Type:    "Error",
		Message: message,
	}
}
