// Package signatures osadza wbudowany pakiet sygnatur detekcyjnych.
package signatures

import "embed"

//go:embed builtin/*.yaml
var Builtin embed.FS
