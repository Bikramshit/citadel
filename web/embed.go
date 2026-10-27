// Package web holds the dashboard's static files, embedded into the binary.
package web

import "embed"

// Files are the dashboard's HTML, JavaScript, and CSS.
//
//go:embed index.html app.js style.css
var Files embed.FS
