//go:build windows

package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"mandatnik/internal/platform"
)

// InstallService registers MandatnikAgent as an automatic LocalSystem service.
func InstallService(configPath string) error {
	if configPath == "" {
		configPath = platform.AgentConfigPath()
	}
	absoluteConfig, err := filepath.Abs(configPath)
	if err != nil {
		return err
	}
	if _, err := os.Stat(absoluteConfig); err != nil {
		return fmt.Errorf("agent config must exist before install: %w", err)
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exe, err = filepath.Abs(exe)
	if err != nil {
		return err
	}
	manager, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to SCM: %w", err)
	}
	defer manager.Disconnect()
	if existing, err := manager.OpenService(ServiceName); err == nil {
		existing.Close()
		return fmt.Errorf("service %s is already installed; run uninstall first", ServiceName)
	}
	args := []string{"run", "-config", absoluteConfig}
	service, err := manager.CreateService(ServiceName, exe, mgr.Config{
		DisplayName: "Мандатник — агент",
		Description: "Collects personal certificate inventory and CryptoPro CSP state.",
		StartType:   mgr.StartAutomatic,
	}, args...)
	if err != nil {
		return fmt.Errorf("create service: %w", err)
	}
	defer service.Close()
	if err := configureRecovery(service); err != nil {
		return err
	}
	return nil
}

func configureRecovery(service *mgr.Service) error {
	actions := []mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 15 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 60 * time.Second},
	}
	if err := service.SetRecoveryActions(actions, 86400); err != nil {
		return fmt.Errorf("set service recovery: %w", err)
	}
	if err := service.SetRecoveryActionsOnNonCrashFailures(true); err != nil {
		return fmt.Errorf("set recovery on non-crash failures: %w", err)
	}
	return nil
}

// ConfigureServiceRecovery is invoked by the MSI after ServiceInstall. It
// applies the same restart policy as a manual install without touching state.
func ConfigureServiceRecovery() error {
	manager, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to SCM: %w", err)
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(ServiceName)
	if err != nil {
		return fmt.Errorf("open service: %w", err)
	}
	defer service.Close()
	return configureRecovery(service)
}

// UninstallProduct delegates to the Windows Installer for an MSI-installed
// product. Local developer installs retain the explicit local fallback.
func UninstallProduct(purge bool) (string, error) {
	if code, ok := installedMSIProduct(); ok {
		// The MSI owns the service and program files. Only an explicit purge
		// removes the per-machine identity/key/queue/logs; repair, upgrade and
		// an ordinary uninstall keep ProgramData state. The GPO-managed
		// agent-config.json lives above AgentDir and is intentionally kept.
		_ = StopService()
		if err := purgeAgentState(purge, platform.AgentDir()); err != nil {
			return "", fmt.Errorf("purge agent state: %w", err)
		}
		logPath, err := startMSIUninstall(code)
		if err != nil {
			return "", err
		}
		if purge {
			return "MSI uninstall started; agent state purged; log: " + logPath, nil
		}
		return "MSI uninstall started; agent identity and state preserved; log: " + logPath, nil
	}
	if err := UninstallService(purge); err != nil {
		return "", err
	}
	if purge {
		return "local service removed; agent state purged", nil
	}
	return "local service removed; agent identity and state preserved", nil
}

var msiProductCodePattern = regexp.MustCompile(`^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$`)

func installedMSIProduct() (string, bool) {
	root, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`, registry.READ)
	if err != nil {
		return "", false
	}
	defer root.Close()
	names, err := root.ReadSubKeyNames(-1)
	if err != nil {
		return "", false
	}
	for _, name := range names {
		if !msiProductCodePattern.MatchString(name) {
			continue
		}
		key, err := registry.OpenKey(root, name, registry.READ)
		if err != nil {
			continue
		}
		displayName, _, _ := key.GetStringValue("DisplayName")
		publisher, _, _ := key.GetStringValue("Publisher")
		key.Close()
		if strings.EqualFold(displayName, "Мандатник — агент") && strings.EqualFold(publisher, "Мандатник") {
			return strings.ToUpper(name), true
		}
	}
	return "", false
}

func startMSIUninstall(productCode string) (string, error) {
	if !msiProductCodePattern.MatchString(productCode) {
		return "", fmt.Errorf("invalid MSI product code")
	}
	logPath := filepath.Join(os.TempDir(), "mandatnik-agent-uninstall-"+time.Now().UTC().Format("20060102T150405Z")+".log")
	msiexec := filepath.Join(os.Getenv("SystemRoot"), "System32", "msiexec.exe")
	cmd := exec.Command(msiexec, "/x", productCode, "/qn", "/norestart", "/l*v", logPath)
	cmd.Dir = os.TempDir()
	null, nullErr := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if nullErr == nil {
		defer null.Close()
		cmd.Stdin = null
		cmd.Stdout = null
		cmd.Stderr = null
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x00000008 | 0x00000200 | 0x01000000}
	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("start MSI uninstall: %w", err)
	}
	// Windows Installer starts in its own process; this CLI exits immediately
	// so the installed EXE is not held open when the file table is removed.
	return logPath, nil
}

// UninstallService stops and deletes the service. purge also removes the
// agent's own state (identity, key, queue, logs), never the GPO config file.
func UninstallService(purge bool) error {
	manager, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to SCM: %w", err)
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(ServiceName)
	if err != nil {
		return fmt.Errorf("open service: %w", err)
	}
	defer service.Close()
	status, err := service.Query()
	if err == nil && status.State != svc.Stopped {
		_, _ = service.Control(svc.Stop)
		_ = waitForState(service, svc.Stopped, 60*time.Second)
	}
	if err := service.Delete(); err != nil {
		return fmt.Errorf("delete service: %w", err)
	}
	if purge {
		if err := purgeAgentState(true, platform.AgentDir()); err != nil {
			return fmt.Errorf("purge agent state: %w", err)
		}
	}
	return nil
}

// StartService starts the service and waits for the running state.
func StartService() error {
	manager, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to SCM: %w", err)
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(ServiceName)
	if err != nil {
		return fmt.Errorf("open service: %w", err)
	}
	defer service.Close()
	if err := service.Start(); err != nil {
		return fmt.Errorf("start service: %w", err)
	}
	return waitForState(service, svc.Running, 60*time.Second)
}

// StopService stops the service and waits for the stopped state.
func StopService() error {
	manager, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to SCM: %w", err)
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(ServiceName)
	if err != nil {
		return fmt.Errorf("open service: %w", err)
	}
	defer service.Close()
	if _, err := service.Control(svc.Stop); err != nil {
		return fmt.Errorf("stop service: %w", err)
	}
	return waitForState(service, svc.Stopped, 120*time.Second)
}

func waitForState(service *mgr.Service, wanted svc.State, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		status, err := service.Query()
		if err != nil {
			return err
		}
		if status.State == wanted {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("service did not reach state %s within %s", stateName(wanted), timeout)
}

func stateName(state svc.State) string {
	switch state {
	case svc.Stopped:
		return "STOPPED"
	case svc.StartPending:
		return "START_PENDING"
	case svc.StopPending:
		return "STOP_PENDING"
	case svc.Running:
		return "RUNNING"
	case svc.ContinuePending:
		return "CONTINUE_PENDING"
	case svc.PausePending:
		return "PAUSE_PENDING"
	case svc.Paused:
		return "PAUSED"
	default:
		return fmt.Sprintf("STATE_%d", state)
	}
}

// QueryService returns a secret-free status snapshot.
func QueryService() (ServiceInfo, error) {
	manager, err := mgr.Connect()
	if err != nil {
		return ServiceInfo{}, fmt.Errorf("connect to SCM: %w", err)
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(ServiceName)
	if err != nil {
		return ServiceInfo{}, fmt.Errorf("open service: %w", err)
	}
	defer service.Close()
	status, err := service.Query()
	if err != nil {
		return ServiceInfo{}, err
	}
	info := ServiceInfo{Name: ServiceName, State: stateName(status.State), ProcessID: status.ProcessId}
	if config, err := service.Config(); err == nil {
		info.BinaryPath = config.BinaryPathName
	}
	return info, nil
}

// ResetIdentity archives the agent's identity/key/state so a new identity is
// created on the next start. It requires the service to be stopped and is an
// explicit administrator action; normal code never regenerates silently.
func ResetIdentity() (string, error) {
	if info, err := QueryService(); err == nil && info.State == "RUNNING" {
		return "", fmt.Errorf("stop the service before resetting identity")
	}
	stamp := time.Now().UTC().Format("20060102T150405Z")
	backup := filepath.Join(platform.AgentDir(), "identity-backup-"+stamp)
	if err := os.MkdirAll(backup, 0o755); err != nil {
		return "", err
	}
	for _, name := range []string{
		"identity.dpapi", "pending_rename.dpapi", "pending_rename.accepted", "identity-public.json",
		"state.json", "jobs.json", "registration-state.json", "queue", "encryption.dpapi", "task-journal.dpapi",
	} {
		source := filepath.Join(platform.AgentDir(), name)
		if _, err := os.Stat(source); err != nil {
			continue
		}
		if err := os.Rename(source, filepath.Join(backup, name)); err != nil {
			return "", fmt.Errorf("archive %s: %w", name, err)
		}
	}
	if err := secureState(backup); err != nil {
		return backup, err
	}
	return backup, nil
}

// Diagnostics returns a compact, secret-free agent diagnostic snapshot.
func Diagnostics() (string, error) {
	var builder strings.Builder
	info, err := QueryService()
	if err != nil {
		builder.WriteString("service: " + err.Error() + "\n")
	} else {
		builder.WriteString(fmt.Sprintf("service: %s %s pid=%d\n", info.Name, info.State, info.ProcessID))
		if info.BinaryPath != "" {
			builder.WriteString("binary: " + info.BinaryPath + "\n")
		}
	}
	if identity, err := readPublicIdentity(); err == nil {
		builder.WriteString(fmt.Sprintf("identity uuid: %s\n", identity.UUID))
		builder.WriteString(fmt.Sprintf("identity hostname: %s\n", identity.Hostname))
	} else {
		builder.WriteString("identity: not initialized\n")
	}
	if stateRaw, err := os.ReadFile(platform.AgentStatePath()); err == nil {
		var state map[string]any
		if json.Unmarshal(stateRaw, &state) == nil {
			builder.WriteString(fmt.Sprintf("state: %v\n", state))
		}
	}
	if notice, err := loadRegistrationNotice(); err == nil && notice.State != "" {
		builder.WriteString(fmt.Sprintf("registration: %s", notice.State))
		if notice.RequestID != "" {
			builder.WriteString(" request_id=" + notice.RequestID)
		}
		if notice.Message != "" {
			builder.WriteString(" — " + notice.Message)
		}
		builder.WriteString("\n")
	}
	queue, _ := os.ReadDir(platform.AgentQueueDir())
	builder.WriteString(fmt.Sprintf("queue items: %d\n", len(queue)))
	diagnostics := filepath.Join(platform.AgentDir(), "diagnostics")
	if entries, err := os.ReadDir(diagnostics); err == nil {
		names := make([]string, 0, len(entries))
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		sort.Strings(names)
		builder.WriteString(fmt.Sprintf("diagnostic files: %d\n", len(names)))
	}
	if raw, err := os.ReadFile(filepath.Join(platform.AgentLogDir(), "current.txt")); err == nil {
		lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
		if len(lines) > 20 {
			lines = lines[len(lines)-20:]
		}
		builder.WriteString("last log lines:\n")
		for _, line := range lines {
			builder.WriteString("  " + line + "\n")
		}
	}
	return builder.String(), nil
}
