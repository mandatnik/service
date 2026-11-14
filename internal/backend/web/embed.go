// Package web embeds the production admin bundle. Vite emits exactly one
// HTML, one CSS and one JavaScript file; no CDN or runtime Node server is
// required by the shipped backend.
package web

import (
	"embed"
	"io/fs"
)

//go:embed dist
var embedded embed.FS

// FS returns the embedded asset root.
func FS() (fs.FS, error) {
	return fs.Sub(embedded, "dist")
}
