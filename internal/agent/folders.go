package agent

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"telehack2026/internal/certparse"
	"telehack2026/internal/protocol"
)

const maxFolderDepth = 64

var certificateExtensions = map[string]bool{
	".cer": true,
	".crt": true,
	".pem": true,
}

// ScanFolders scans every configured directory independently. A malformed
// file or an unreadable subtree makes only that folder source partial; the
// remaining folders and profiles continue.
func ScanFolders(ctx context.Context, cfg protocol.AgentConfig, logger *Logger) []protocol.SourceResult {
	out := make([]protocol.SourceResult, 0, len(cfg.CertDirectories))
	for _, configured := range cfg.CertDirectories {
		if ctx.Err() != nil {
			break
		}
		out = append(out, scanFolder(ctx, configured, cfg, logger))
	}
	return out
}

func scanFolder(ctx context.Context, configured string, cfg protocol.AgentConfig, logger *Logger) protocol.SourceResult {
	clean := filepath.Clean(configured)
	source := protocol.SourceResult{
		SourceType:   "folder",
		SourceKey:    clean,
		DisplayName:  clean,
		Path:         clean,
		Complete:     true,
		Certificates: []protocol.ObservedCertificate{},
	}
	info, err := os.Stat(clean)
	if err != nil {
		source.Complete = false
		source.Error = boundError(fmt.Sprintf("stat folder: %v", err))
		logSourceError(logger, clean, source.Error)
		return source
	}
	if !info.IsDir() {
		source.Complete = false
		source.Error = "configured path is not a directory"
		logSourceError(logger, clean, source.Error)
		return source
	}

	seen := make(map[string]int)
	fileCount := 0
	stop := errors.New("folder file limit reached")
	err = filepath.WalkDir(clean, func(path string, entry fs.DirEntry, walkErr error) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if walkErr != nil {
			source.Complete = false
			appendSourceError(&source, fmt.Sprintf("walk %s: %v", path, walkErr))
			if entry != nil && entry.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if path != clean {
			if depth := pathDepth(clean, path); depth > maxFolderDepth {
				source.Complete = false
				appendSourceError(&source, fmt.Sprintf("directory depth limit reached at %s", path))
				if entry.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
		}
		if entry.Type()&os.ModeSymlink != 0 {
			if entry.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if entry.IsDir() {
			return nil
		}
		if !certificateExtensions[strings.ToLower(filepath.Ext(path))] {
			return nil
		}
		fileCount++
		if fileCount > cfg.MaxFiles {
			source.Complete = false
			appendSourceError(&source, fmt.Sprintf("file limit %d reached", cfg.MaxFiles))
			return stop
		}
		scanCertificateFile(ctx, &source, path, cfg.MaxFileBytes, seen, logger)
		return nil
	})
	if err != nil && !errors.Is(err, stop) && ctx.Err() == nil {
		source.Complete = false
		appendSourceError(&source, fmt.Sprintf("walk folder: %v", err))
	}
	sort.Slice(source.Certificates, func(i, j int) bool {
		return source.Certificates[i].SHA256 < source.Certificates[j].SHA256
	})
	sort.Slice(source.Files, func(i, j int) bool {
		if source.Files[i].Path == source.Files[j].Path {
			return source.Files[i].SHA256 < source.Files[j].SHA256
		}
		return source.Files[i].Path < source.Files[j].Path
	})
	return source
}

func scanCertificateFile(ctx context.Context, source *protocol.SourceResult, path string, maxBytes int64, seen map[string]int, logger *Logger) {
	if ctx.Err() != nil {
		return
	}
	info, err := os.Stat(path)
	if err != nil {
		source.Complete = false
		appendSourceError(source, fmt.Sprintf("stat %s: %v", path, err))
		source.Files = append(source.Files, protocol.ObservedFile{Path: path, Error: boundError(err.Error())})
		return
	}
	if info.Size() > maxBytes {
		source.Complete = false
		appendSourceError(source, fmt.Sprintf("file %s exceeds max_file_bytes", path))
		source.Files = append(source.Files, protocol.ObservedFile{Path: path, Error: "file exceeds max_file_bytes"})
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		source.Complete = false
		appendSourceError(source, fmt.Sprintf("read %s: %v", path, err))
		source.Files = append(source.Files, protocol.ObservedFile{Path: path, Error: boundError(err.Error())})
		return
	}
	if int64(len(data)) > maxBytes {
		source.Complete = false
		appendSourceError(source, fmt.Sprintf("file %s exceeds max_file_bytes", path))
		source.Files = append(source.Files, protocol.ObservedFile{Path: path, Error: "file exceeds max_file_bytes"})
		return
	}
	certs, parseErr := certparse.ParseFile(stripWhitespace(data))
	if parseErr != nil {
		source.Complete = false
	}
	for _, cert := range certs {
		source.Files = append(source.Files, protocol.ObservedFile{Path: path, SHA256: cert.SHA256})
		if _, exists := seen[cert.SHA256]; exists {
			continue
		}
		observation, observationErr := observeDER(cert.Raw)
		if observationErr != nil {
			source.Complete = false
			appendSourceError(source, fmt.Sprintf("parse certificate fields %s: %v", path, observationErr))
		}
		seen[cert.SHA256] = len(source.Certificates)
		source.Certificates = append(source.Certificates, observation)
	}
	if parseErr != nil {
		appendSourceError(source, fmt.Sprintf("file %s: %v", path, parseErr))
		source.Files = append(source.Files, protocol.ObservedFile{Path: path, Error: boundError(parseErr.Error())})
		if logger != nil {
			logger.Logf("certificate file failed: %s: %v", path, parseErr)
		}
	}
}

func pathDepth(root, path string) int {
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == "." {
		return 0
	}
	return len(strings.Split(rel, string(os.PathSeparator)))
}

func appendSourceError(source *protocol.SourceResult, message string) {
	if source.Error == "" {
		source.Error = boundError(message)
	} else if len(source.Error) < protocol.MaxErrorBytes {
		source.Error = boundError(source.Error + "; " + message)
	}
}

func boundError(value string) string {
	if len(value) <= protocol.MaxErrorBytes {
		return value
	}
	return value[:protocol.MaxErrorBytes]
}

func logSourceError(logger *Logger, path, message string) {
	if logger != nil {
		logger.Logf("certificate source failed: %s: %s", path, message)
	}
}
