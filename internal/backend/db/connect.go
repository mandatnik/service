// Package db opens SQL Server connections with TLS validation and owns the
// embedded migration runner.
package db

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"fmt"
	"os"
	"time"

	mssql "github.com/microsoft/go-mssqldb"
	"github.com/microsoft/go-mssqldb/msdsn"
	"mandatnik/internal/backend/config"
)

// Open opens the application database with the runtime credentials.
func Open(ctx context.Context, cfg config.DB) (*sql.DB, error) {
	password, err := cfg.Password()
	if err != nil {
		return nil, err
	}
	return OpenAs(ctx, cfg, cfg.User, password, cfg.Database)
}

// OpenAs opens a connection as an explicit login. It is used by bootstrap for
// the sa connection and by normal startup for the runtime login.
func OpenAs(ctx context.Context, cfg config.DB, user, password, database string) (*sql.DB, error) {
	tlsConfig, err := buildTLSConfig(cfg)
	if err != nil {
		return nil, err
	}
	connector := mssql.NewConnectorConfig(msdsn.Config{
		Host:                   cfg.Server,
		Port:                   uint64(cfg.Port),
		Database:               database,
		User:                   user,
		Password:               password,
		Encryption:             msdsn.EncryptionRequired,
		TLSConfig:              tlsConfig,
		TrustServerCertificate: cfg.TrustServerCertificate,
		Protocols:              []string{"tcp"},
		AppName:                "MandatnikBackend",
		DialTimeout:            time.Duration(cfg.ConnectTimeoutSeconds) * time.Second,
		ConnTimeout:            time.Duration(cfg.ConnectTimeoutSeconds) * time.Second,
	})
	pool := sql.OpenDB(connector)
	pool.SetMaxOpenConns(20)
	pool.SetMaxIdleConns(10)
	pool.SetConnMaxLifetime(30 * time.Minute)
	pool.SetConnMaxIdleTime(5 * time.Minute)
	pingCtx, cancel := context.WithTimeout(ctx, time.Duration(cfg.ConnectTimeoutSeconds)*time.Second)
	defer cancel()
	if err := pool.PingContext(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("connect to SQL Server %s:%d/%s as %s: %w", cfg.Server, cfg.Port, database, user, err)
	}
	return pool, nil
}

func buildTLSConfig(cfg config.DB) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	if cfg.ServerName != "" {
		tlsConfig.ServerName = cfg.ServerName
	} else {
		tlsConfig.ServerName = cfg.Server
	}
	if cfg.CAFile != "" {
		pemBytes, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read SQL CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, fmt.Errorf("SQL CA file %s contains no PEM certificates", cfg.CAFile)
		}
		tlsConfig.RootCAs = pool
	}
	if cfg.TrustServerCertificate {
		// This is reachable only with the explicit allow_insecure_db_tls flag
		// and is intended for diagnostics, never as a silent default.
		tlsConfig.InsecureSkipVerify = true
	}
	return tlsConfig, nil
}

// Healthy runs a minimal query against the application database.
func Healthy(ctx context.Context, pool *sql.DB) error {
	if pool == nil {
		return fmt.Errorf("nil database pool")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var value int
	return pool.QueryRowContext(ctx, "SELECT 1").Scan(&value)
}
