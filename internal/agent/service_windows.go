//go:build windows

package agent

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"time"

	"golang.org/x/sys/windows/svc"
)

func runPlatform(configPath string) error {
	isService, err := svc.IsWindowsService()
	if err != nil {
		return fmt.Errorf("detect service context: %w", err)
	}
	if isService {
		return svc.Run(ServiceName, &serviceHandler{configPath: configPath})
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	return runAgentRuntime(ctx, configPath)
}

type serviceHandler struct {
	configPath string
}

func (h *serviceHandler) Execute(_ []string, requests <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- runAgentRuntime(ctx, h.configPath)
	}()
	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case err := <-done:
			if err != nil {
				fmt.Fprintln(os.Stderr, "mandatnik-agent service stopped:", err)
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
						fmt.Fprintln(os.Stderr, "mandatnik-agent service stop:", err)
						return false, 1
					}
					return false, 0
				case <-time.After(120 * time.Second):
					return false, 1
				}
			default:
				// Unknown control codes are ignored; the service remains running.
			}
		}
	}
}
