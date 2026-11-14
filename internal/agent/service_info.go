package agent

// ServiceName is the SCM service name used by install/status/uninstall.
const ServiceName = "TelehackAgent"

// ServiceInfo is a secret-free service diagnostic snapshot.
type ServiceInfo struct {
	Name       string `json:"name"`
	State      string `json:"state"`
	StartType  string `json:"start_type,omitempty"`
	BinaryPath string `json:"binary_path,omitempty"`
	ProcessID  uint32 `json:"process_id,omitempty"`
}
