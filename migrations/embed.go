// Package migrations embeds the schema so the binary carries its own migrations and
// nothing has to be shipped alongside it.
package migrations

import "embed"

//go:embed *.sql
var FS embed.FS
