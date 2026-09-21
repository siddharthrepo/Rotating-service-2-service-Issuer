// Package web embeds the dashboard's templates and static assets so the binary is
// self-contained -- no asset directory to ship or mount alongside it.
package web

import "embed"

//go:embed templates/*.html
var Templates embed.FS

//go:embed static/*
var Static embed.FS
