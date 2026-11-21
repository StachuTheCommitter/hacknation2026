// Package web osadza zbudowany interfejs (npm run build → web/dist).
package web

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var dist embed.FS

// UI zwraca system plików z interfejsem (nil, gdy UI nie zostało zbudowane).
func UI() fs.FS {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		return nil
	}
	if _, err := fs.Stat(sub, "index.html"); err != nil {
		return nil
	}
	return sub
}
