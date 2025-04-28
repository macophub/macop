//go:build !windows

package core

import "os"

func setSparse(*os.File) {
}
