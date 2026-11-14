package backend

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Logger writes plain-text backend events. It never receives request bodies,
// passwords or certificate private material.
type Logger struct {
	mu       sync.Mutex
	file     *os.File
	path     string
	size     int64
	maxBytes int64
}

const backendLogMaxBytes = 10 * 1024 * 1024

func openLogger(path string) (*Logger, error) {
	if path == "" {
		return &Logger{}, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create backend log directory: %w", err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open backend log: %w", err)
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}
	return &Logger{file: file, path: path, size: info.Size(), maxBytes: backendLogMaxBytes}, nil
}

// Logf writes one millisecond timestamped line to the file and stderr.
func (l *Logger) Logf(format string, args ...any) {
	line := fmt.Sprintf("%s - %s\n", time.Now().Format("2006-01-02 15:04:05.000"), fmt.Sprintf(format, args...))
	if l == nil {
		fmt.Fprint(os.Stderr, line)
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file != nil && l.size+int64(len(line)) > l.maxBytes {
		_ = l.rotateLocked()
	}
	if l.file != nil {
		if n, err := l.file.WriteString(line); err == nil {
			l.size += int64(n)
		}
	}
	fmt.Fprint(os.Stderr, line)
}

func (l *Logger) rotateLocked() error {
	if l.file != nil {
		_ = l.file.Close()
		l.file = nil
	}
	previous := l.path + ".previous"
	_ = os.Remove(previous)
	if err := os.Rename(l.path, previous); err != nil && !os.IsNotExist(err) {
		file, openErr := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if openErr == nil {
			l.file = file
			if info, statErr := file.Stat(); statErr == nil {
				l.size = info.Size()
			}
		}
		return err
	}
	file, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	l.file = file
	l.size = 0
	return nil
}

// Close flushes the file.
func (l *Logger) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return nil
	}
	err := l.file.Close()
	l.file = nil
	return err
}
