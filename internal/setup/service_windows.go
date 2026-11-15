//go:build windows

// Windows service management for the backend: SCM registration, start/stop,
// logon-account configuration, the local service account creation and
// SeServiceLogonRight.
package setup

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"mandatnik/internal/backend"
)

// ServiceName is the SCM display name of the backend service.
const ServiceName = "MandatnikBackend"

// ServiceStatus is a platform-neutral snapshot.
type ServiceStatus struct {
	Installed bool
	Running   bool
	State     string
	PID       uint32
}

// InstallService registers the backend service with automatic start.
func InstallService(exePath string, args []string) error {
	if _, err := os.Stat(exePath); err != nil {
		return fmt.Errorf("файл службы %s не найден: %w", exePath, err)
	}
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("подключаюсь к диспетчеру служб: %w", err)
	}
	defer m.Disconnect()
	if existing, err := m.OpenService(ServiceName); err == nil {
		_ = existing.Close()
		return fmt.Errorf("служба %s уже зарегистрирована; сначала выполните service-uninstall", ServiceName)
	}
	config := mgr.Config{
		DisplayName: "Мандатник Backend",
		Description: "Бэкенд «Мандатник»: агентский, административный и интеграционный HTTPS API",
		StartType:   mgr.StartAutomatic,
	}
	service, err := m.CreateService(ServiceName, exePath, config, args...)
	if err != nil {
		return fmt.Errorf("создаю службу: %w", err)
	}
	defer service.Close()
	return nil
}

// ConfigureServiceAccount switches the service logon account and grants the
// SeServiceLogonRight. Local accounts are addressed as ".\name".
func ConfigureServiceAccount(account, password string) error {
	if strings.TrimSpace(account) == "" {
		return errors.New("учётная запись службы не указана")
	}
	sid, _, _, err := windows.LookupSID("", account)
	if err != nil {
		return fmt.Errorf("определяю SID учётной записи %s: %w", account, err)
	}
	if err := grantServiceLogonRight(sid); err != nil {
		return err
	}
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("подключаюсь к диспетчеру служб: %w", err)
	}
	defer m.Disconnect()
	service, err := m.OpenService(ServiceName)
	if err != nil {
		return fmt.Errorf("служба %s не зарегистрирована: %w", ServiceName, err)
	}
	defer service.Close()
	if err := changeServiceAccount(service.Handle, account, password); err != nil {
		return err
	}
	return nil
}

const serviceNoChange = 0xFFFFFFFF

func changeServiceAccount(handle windows.Handle, account, password string) error {
	accountPtr, err := windows.UTF16PtrFromString(account)
	if err != nil {
		return err
	}
	passPtr, err := windows.UTF16PtrFromString(password)
	if err != nil {
		return err
	}
	return windows.ChangeServiceConfig(handle, serviceNoChange, serviceNoChange, serviceNoChange,
		nil, nil, nil, nil, accountPtr, passPtr, nil)
}

// StartService starts the backend service and waits until it reports running.
func StartService(timeout time.Duration) error {
	service, err := openService()
	if err != nil {
		return err
	}
	defer service.Close()
	if err := service.Start(); err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
			return nil
		}
		return fmt.Errorf("запускаю службу: %w", err)
	}
	return waitRunning(service, timeout)
}

// StopService stops the backend service.
func StopService(timeout time.Duration) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	service, err := m.OpenService(ServiceName)
	if err != nil {
		return nil // not installed
	}
	defer service.Close()
	if _, err := service.Control(svc.Stop); err != nil {
		return fmt.Errorf("останавливаю службу: %w", err)
	}
	return waitState(service, timeout, svc.Stopped)
}

// UninstallService removes the backend service registration.
func UninstallService() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	service, err := m.OpenService(ServiceName)
	if err != nil {
		return nil
	}
	defer service.Close()
	if err := service.Delete(); err != nil {
		return fmt.Errorf("удаляю службу: %w", err)
	}
	return nil
}

// QueryService reports the current state.
func QueryService() (*ServiceStatus, error) {
	m, err := mgr.Connect()
	if err != nil {
		return nil, err
	}
	defer m.Disconnect()
	service, err := m.OpenService(ServiceName)
	if err != nil {
		return &ServiceStatus{Installed: false}, nil
	}
	defer service.Close()
	status, err := service.Query()
	if err != nil {
		return nil, err
	}
	return &ServiceStatus{Installed: true, Running: status.State == svc.Running, State: stateText(status.State), PID: status.ProcessId}, nil
}

func openService() (*mgr.Service, error) {
	m, err := mgr.Connect()
	if err != nil {
		return nil, fmt.Errorf("подключаюсь к диспетчеру служб: %w", err)
	}
	service, err := m.OpenService(ServiceName)
	if err != nil {
		m.Disconnect()
		return nil, fmt.Errorf("служба %s не зарегистрирована: %w", ServiceName, err)
	}
	return service, nil
}

func waitRunning(service *mgr.Service, timeout time.Duration) error {
	return waitState(service, timeout, svc.Running)
}

func waitState(service *mgr.Service, timeout time.Duration, want svc.State) error {
	deadline := time.Now().Add(timeout)
	for {
		status, err := service.Query()
		if err != nil {
			return err
		}
		if status.State == want {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("служба не достигла состояния %q за %s (сейчас: %s)", stateText(want), timeout, stateText(status.State))
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func stateText(state svc.State) string {
	switch state {
	case svc.Stopped:
		return "остановлена"
	case svc.StartPending:
		return "запускается"
	case svc.StopPending:
		return "останавливается"
	case svc.Running:
		return "работает"
	case svc.ContinuePending:
		return "продолжается"
	case svc.PausePending:
		return "приостанавливается"
	case svc.Paused:
		return "приостановлена"
	default:
		return fmt.Sprintf("неизвестное состояние %d", state)
	}
}

// IsServiceContext reports whether this process runs as a Windows service.
func IsServiceContext() (bool, error) {
	return svc.IsWindowsService()
}

// CreateLocalAccount creates a local Windows account with the given password
// through `net user`, reading the password from stdin, so the secret never
// appears in the command line, logs or history.
func CreateLocalAccount(name, password string) error {
	if strings.TrimSpace(name) == "" {
		return errors.New("имя учётной записи не указано")
	}
	if len(password) < 12 {
		return errors.New("пароль учётной записи должен содержать не менее 12 символов")
	}
	cmd := exec.Command("net", "user", name, "/add", "/passwordchg:no", "/active:yes")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("создаю учётную запись: %w", err)
	}
	// `net user ... /add` prompts for the password twice.
	if _, err := fmt.Fprintln(stdin, password); err != nil {
		_ = cmd.Process.Kill()
		return err
	}
	if _, err := fmt.Fprintln(stdin, password); err != nil {
		_ = cmd.Process.Kill()
		return err
	}
	_ = stdin.Close()
	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("создание учётной записи %s не удалось (возможно, она уже существует): %w", name, err)
	}
	sid, _, _, err := windows.LookupSID("", name)
	if err != nil {
		return fmt.Errorf("определяю SID учётной записи %s: %w", name, err)
	}
	return grantServiceLogonRight(sid)
}

// --- SeServiceLogonRight via LSA (raw bindings; x/sys has none) ---

type lsaUnicodeString struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *uint16
}

type lsaObjectAttributes struct {
	Length                   uint32
	RootDirectory            windows.Handle
	ObjectName               *lsaUnicodeString
	Attributes               uint32
	SecurityDescriptor       uintptr
	SecurityQualityOfService uintptr
}

var (
	lsaMod               = windows.NewLazySystemDLL("advapi32.dll")
	procLsaOpenPolicy    = lsaMod.NewProc("LsaOpenPolicy")
	procLsaAddAccountRts = lsaMod.NewProc("LsaAddAccountRights")
	procLsaClose         = lsaMod.NewProc("LsaClose")
)

// grantServiceLogonRight adds SeServiceLogonRight for the account SID.
func grantServiceLogonRight(sid *windows.SID) error {
	var policy windows.Handle
	attrs := lsaObjectAttributes{Length: uint32(unsafe.Sizeof(lsaObjectAttributes{}))}
	nt, _, _ := procLsaOpenPolicy.Call(
		0,
		uintptr(unsafe.Pointer(&attrs)),
		0x00000004|0x00000800, // POLICY_CREATE_ACCOUNT | POLICY_LOOKUP_NAMES
		uintptr(unsafe.Pointer(&policy)),
	)
	if nt != 0 {
		return fmt.Errorf("открываю локальную политику безопасности: NTSTATUS 0x%08x", nt)
	}
	defer procLsaClose.Call(uintptr(policy))
	name := "SeServiceLogonRight"
	utf16, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	right := lsaUnicodeString{Length: uint16(2 * len(name)), MaximumLength: uint16(2 * (len(name) + 1)), Buffer: utf16}
	nt, _, _ = procLsaAddAccountRts.Call(
		uintptr(policy),
		uintptr(unsafe.Pointer(sid)),
		uintptr(unsafe.Pointer(&right)),
		1,
	)
	if nt != 0 {
		return fmt.Errorf("не удалось выдать право входа в качестве службы: NTSTATUS 0x%08x", nt)
	}
	return nil
}

// ServiceRun executes the backend under SCM control.
func ServiceRun(configPath string) error {
	return svc.Run(ServiceName, &backendServiceHandler{configPath: configPath})
}

type backendServiceHandler struct {
	configPath string
}

// Execute implements svc.Handler for the backend service.
func (h *backendServiceHandler) Execute(_ []string, requests <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- backend.ServeWithConfig(ctx, h.configPath)
	}()
	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case err := <-done:
			if err != nil {
				return false, 1
			}
			return false, 0
		case request := <-requests:
			switch request.Cmd {
			case svc.Interrogate:
				changes <- request.CurrentStatus
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending}
				cancel()
				select {
				case err := <-done:
					if err != nil {
						return false, 1
					}
					return false, 0
				case <-time.After(60 * time.Second):
					return false, 1
				}
			default:
			}
		}
	}
}
