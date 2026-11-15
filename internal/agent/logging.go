package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"mandatnik/internal/protocol"
)

// Logger writes plain-text significant events and errors to current.txt and
// previous.txt. Rotation deletes the previous file and never accumulates more
// than two 10 MiB files. Secrets are never passed to this logger.
type Logger struct {
	mu       sync.Mutex
	dir      string
	file     *os.File
	size     int64
	maxBytes int64
}

// OpenLogger creates the log directory and opens current.txt for append.
func OpenLogger(dir string) (*Logger, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create log directory: %w", err)
	}
	logger := &Logger{dir: dir, maxBytes: protocol.LogFileMaxBytes}
	path := logger.currentPath()
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open log: %w", err)
	}
	_ = securePath(path)
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("stat log: %w", err)
	}
	logger.file = file
	logger.size = info.Size()
	return logger, nil
}

func (l *Logger) currentPath() string  { return filepath.Join(l.dir, "current.txt") }
func (l *Logger) previousPath() string { return filepath.Join(l.dir, "previous.txt") }

// Logf writes one line with a millisecond timestamp.
func (l *Logger) Logf(format string, args ...any) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	message := fmt.Sprintf(format, args...)
	line := fmt.Sprintf("%s - %s\n", time.Now().Format("2006-01-02 15:04:05.000"), message)
	if l.size+int64(len(line)) > l.maxBytes {
		if err := l.rotateLocked(); err != nil {
			fmt.Fprintln(os.Stderr, "mandatnik-agent log rotation:", err)
		}
	}
	if l.file == nil {
		return
	}
	n, err := l.file.WriteString(line)
	if err != nil {
		fmt.Fprintln(os.Stderr, "mandatnik-agent log write:", err)
		return
	}
	l.size += int64(n)
}

func (l *Logger) rotateLocked() error {
	if l.file != nil {
		_ = l.file.Close()
		l.file = nil
	}
	_ = os.Remove(l.previousPath())
	if err := os.Rename(l.currentPath(), l.previousPath()); err != nil && !os.IsNotExist(err) {
		// If rename fails, do not lose the current file: truncate only when it
		// is already over the limit is worse than appending. Reopen and report.
		file, openErr := os.OpenFile(l.currentPath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if openErr == nil {
			l.file = file
			if info, statErr := file.Stat(); statErr == nil {
				l.size = info.Size()
			}
		}
		return fmt.Errorf("rotate current log: %w", err)
	}
	file, err := os.OpenFile(l.currentPath(), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("create new current log: %w", err)
	}
	_ = securePath(l.currentPath())
	l.file = file
	l.size = 0
	return nil
}

// Close flushes and closes the logger.
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
