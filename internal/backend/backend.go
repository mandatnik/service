// Package backend implements the single-process portable backend: HTTPS
// listeners, SQL Server persistence, migrations and the agent API.
package backend

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"time"

	"telehack2026/internal/backend/api"
	"telehack2026/internal/backend/config"
	"telehack2026/internal/backend/db"
	"telehack2026/internal/backend/store"
	"telehack2026/internal/protocol"
	"telehack2026/internal/version"
)

// Run loads configuration, applies migrations and serves both listeners in
// one process until interrupted.
func Run(configPath string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	logger, err := openLogger(cfg.LogFile)
	if err != nil {
		return err
	}
	defer logger.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	return serve(ctx, cfg, logger)
}

func serve(ctx context.Context, cfg config.Config, logger *Logger) error {
	logger.Logf("backend starting: %s", version.String())
	pool, err := db.Open(ctx, cfg.DB)
	if err != nil {
		logger.Logf("database open failed: %v", err)
		return err
	}
	defer pool.Close()
	if err := db.Migrate(ctx, pool, logger.Logf); err != nil {
		logger.Logf("migration failed: %v", err)
		return err
	}
	if err := db.Healthy(ctx, pool); err != nil {
		logger.Logf("database health check failed: %v", err)
		return err
	}
	persistence := store.New(pool)
	apiServer := api.New(persistence, logger, cfg)
	agentServer := newHTTPServer(cfg.AgentListen, apiServer.AgentHandler())
	adminServer := newHTTPServer(cfg.AdminListen, apiServer.AdminHandler())
	logger.Logf("backend ready: agent=%s admin=%s db=%s/%s", cfg.AgentListen, cfg.AdminListen, cfg.DB.Server, cfg.DB.Database)

	errorChannel := make(chan error, 2)
	var wg sync.WaitGroup
	start := func(name string, server *http.Server) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			logger.Logf("%s listener starting on %s", name, server.Addr)
			if err := server.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errorChannel <- fmt.Errorf("%s listener: %w", name, err)
			}
		}()
	}
	start("agent", agentServer)
	start("admin", adminServer)

	var runErr error
	select {
	case <-ctx.Done():
		logger.Logf("shutdown requested")
	case runErr = <-errorChannel:
		logger.Logf("listener failed: %v", runErr)
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := agentServer.Shutdown(shutdownCtx); err != nil {
		logger.Logf("agent shutdown: %v", err)
	}
	if err := adminServer.Shutdown(shutdownCtx); err != nil {
		logger.Logf("admin shutdown: %v", err)
	}
	wg.Wait()
	logger.Logf("backend stopped")
	return runErr
}

func newHTTPServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: protocol.HTTPReadHeaderTimeout,
		ReadTimeout:       protocol.HTTPReadTimeout,
		WriteTimeout:      protocol.HTTPWriteTimeout,
		IdleTimeout:       protocol.HTTPIdleTimeout,
		MaxHeaderBytes:    protocol.HTTPMaxHeaderBytes,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}
}

// Bootstrap creates the application database and runtime login. The
// administrative password is supplied via TELEHACK_SA_PASSWORD.
func Bootstrap(configPath string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	logger, err := openLogger(cfg.LogFile)
	if err != nil {
		return err
	}
	defer logger.Close()
	saPassword := os.Getenv("TELEHACK_SA_PASSWORD")
	if saPassword == "" {
		return errors.New("TELEHACK_SA_PASSWORD is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := db.Bootstrap(ctx, cfg, saPassword); err != nil {
		logger.Logf("bootstrap failed: %v", err)
		return err
	}
	logger.Logf("bootstrap complete: database=%s user=%s", cfg.DB.Database, cfg.DB.User)
	fmt.Printf("database %s and login %s are ready\n", cfg.DB.Database, cfg.DB.User)
	return nil
}

// Migrate applies embedded migrations and reports the version list.
func Migrate(configPath string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	logger, err := openLogger(cfg.LogFile)
	if err != nil {
		return err
	}
	defer logger.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	pool, err := db.Open(ctx, cfg.DB)
	if err != nil {
		return err
	}
	defer pool.Close()
	if err := db.Migrate(ctx, pool, logger.Logf); err != nil {
		return err
	}
	versions, err := db.MigrationStatus(ctx, pool)
	if err != nil {
		return err
	}
	fmt.Printf("applied migrations: %v\n", versions)
	return nil
}

// Health is exported for the acceptance tool to check the database without
// starting HTTP listeners.
func Health(ctx context.Context, cfg config.Config) error {
	pool, err := db.Open(ctx, cfg.DB)
	if err != nil {
		return err
	}
	defer pool.Close()
	return db.Healthy(ctx, pool)
}
