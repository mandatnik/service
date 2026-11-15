//go:build windows

package backend

import (
	"context"
	"time"

	"golang.org/x/sys/windows/svc"
)

// RunPlatform handles the Windows service context transparently: under SCM
// the backend is driven by control codes instead of Ctrl+C.
func RunPlatform(configPath string) error {
	isService, err := svc.IsWindowsService()
	if err != nil {
		return Run(configPath)
	}
	if isService {
		return svc.Run("MandatnikBackend", &backendServiceHandler{configPath: configPath})
	}
	return Run(configPath)
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
		done <- ServeWithConfig(ctx, h.configPath)
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
