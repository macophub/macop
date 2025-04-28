package envconfig

import (
	"os"
	"path/filepath"
	"strings"
)

// McpPath returns the path to the models directory. McpPath directory can be configured via the MACOP_MCPS environment variable.
// Default is $HOME/.macop/mcps
func McpPath() string {
	if s := Var("MACOP_MCPS"); s != "" {
		return s
	}

	home, err := os.UserHomeDir()
	if err != nil {
		panic(err)
	}

	return filepath.Join(home, ".macop", "mcps")
}

type EnvVar struct {
	Name        string
	Value       any
	Description string
}

// Var returns an environment variable stripped of leading and trailing quotes or spaces
func Var(key string) string {
	return strings.Trim(strings.TrimSpace(os.Getenv(key)), "\"'")
}
