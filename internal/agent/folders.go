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
	"telehack2026/internal/folderpolicy"
	"telehack2026/internal/protocol"
)

const maxFolderDepth = 64

// ScanFolders evaluates assigned policies into one folder observation scope.
// A partial traversal never authorizes removal of previously known files.
func ScanFolders(ctx context.Context, cfg protocol.AgentConfig, logger *Logger) []protocol.SourceResult {
	// A stable aggregate scope allows revoked policies and exclusions to remove
	// old observations on a successful scan, including when no policy is assigned.
	source := protocol.SourceResult{SourceType: "folder", SourceKey: "folder-policies", DisplayName: "Политики папок", Path: "folder-policies", Complete: true, Certificates: []protocol.ObservedCertificate{}}
	type compiled struct {
		policy *folderpolicy.Policy
		level  string
	}
	policies := []compiled{}
	for _, assignment := range cfg.FolderPolicies {
		p, err := folderpolicy.Compile(assignment.Rules)
		if err != nil {
			source.Complete = false
			appendSourceError(&source, err.Error())
			continue
		}
		policies = append(policies, compiled{p, assignment.Level})
	}
	seenFiles := map[string]bool{}
	seenCerts := map[string]int{}
	count := 0
	stop := errors.New("file limit reached")
	for _, assignment := range policies {
		for _, root := range assignment.policy.Roots {
			clean := filepath.Clean(filepath.FromSlash(root))
			err := filepath.WalkDir(clean, func(file string, entry fs.DirEntry, walkErr error) error {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				if walkErr != nil {
					source.Complete = false
					appendSourceError(&source, fmt.Sprintf("walk %s: %v", file, walkErr))
					if entry != nil && entry.IsDir() {
						return fs.SkipDir
					}
					return nil
				}
				if entry.Type()&os.ModeSymlink != 0 {
					return nil
				}
				if entry.IsDir() {
					if assignment.level == "group" {
						for _, direct := range policies {
							if direct.level == "machine" && direct.policy.Excludes(filepath.ToSlash(file)) && !direct.policy.MayContain(filepath.ToSlash(file)) {
								return fs.SkipDir
							}
						}
					}
					if !assignment.policy.MayContain(filepath.ToSlash(file)) {
						return fs.SkipDir
					}
					if pathDepth(clean, file) > maxFolderDepth {
						source.Complete = false
						appendSourceError(&source, "directory depth limit reached")
						return fs.SkipDir
					}
					return nil
				}
				if !strings.EqualFold(filepath.Ext(file), ".cer") || !assignment.policy.Includes(filepath.ToSlash(file)) {
					return nil
				}
				if assignment.level == "group" {
					for _, direct := range policies {
						if direct.level == "machine" && direct.policy.Excludes(filepath.ToSlash(file)) {
							return nil
						}
					}
				}
				key := strings.ToLower(file)
				if seenFiles[key] {
					return nil
				}
				seenFiles[key] = true
				count++
				if count > cfg.MaxFiles {
					source.Complete = false
					appendSourceError(&source, fmt.Sprintf("file limit %d reached", cfg.MaxFiles))
					return stop
				}
				scanCertificateFile(ctx, &source, file, cfg.MaxFileBytes, seenCerts, logger)
				return nil
			})
			if err != nil {
				source.Complete = false
				appendSourceError(&source, err.Error())
			}
			if ctx.Err() != nil || errors.Is(err, stop) {
				break
			}
		}
		if ctx.Err() != nil || count > cfg.MaxFiles {
			break
		}
	}
	if ctx.Err() != nil {
		source.Complete = false
		appendSourceError(&source, ctx.Err().Error())
	}
	sort.Slice(source.Files, func(i, j int) bool {
		if source.Files[i].Path == source.Files[j].Path {
			return source.Files[i].SHA256 < source.Files[j].SHA256
		}
		return source.Files[i].Path < source.Files[j].Path
	})
	sort.Slice(source.Certificates, func(i, j int) bool { return source.Certificates[i].SHA256 < source.Certificates[j].SHA256 })
	if !source.Complete {
		logSourceError(logger, source.SourceKey, source.Error)
	}
	return []protocol.SourceResult{source}
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
