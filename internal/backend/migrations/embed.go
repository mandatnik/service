// Package migrations embeds the SQL Server schema migrations.
package migrations

import (
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
)

//go:embed *.sql
var embedded embed.FS

// File is one embedded migration.
type File struct {
	Version  int
	Name     string
	Contents string
}

// All returns migrations sorted by version. File names must start with a
// numeric version followed by an underscore.
func All() ([]File, error) {
	entries, err := fs.ReadDir(embedded, ".")
	if err != nil {
		return nil, err
	}
	var files []File
	seen := make(map[int]string)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		version, err := parseVersion(entry.Name())
		if err != nil {
			return nil, err
		}
		if previous, exists := seen[version]; exists {
			return nil, fmt.Errorf("duplicate migration version %d: %s and %s", version, previous, entry.Name())
		}
		seen[version] = entry.Name()
		data, err := embedded.ReadFile(entry.Name())
		if err != nil {
			return nil, err
		}
		files = append(files, File{Version: version, Name: entry.Name(), Contents: string(data)})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Version < files[j].Version })
	for i, file := range files {
		if file.Version != i+1 {
			return nil, fmt.Errorf("migration versions must be consecutive from 1; found %d at position %d", file.Version, i+1)
		}
	}
	return files, nil
}

func parseVersion(name string) (int, error) {
	underscore := strings.IndexByte(name, '_')
	if underscore <= 0 {
		return 0, fmt.Errorf("migration %s has no numeric prefix", name)
	}
	version, err := strconv.Atoi(name[:underscore])
	if err != nil || version < 1 {
		return 0, fmt.Errorf("migration %s has an invalid version", name)
	}
	return version, nil
}
