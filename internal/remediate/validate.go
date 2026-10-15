// SPDX-License-Identifier: Apache-2.0

package remediate

import (
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"strings"
)

// Validate checks that rewritten source still parses. checked is false when
// no validator is available for the language (the change is then flagged for
// manual review rather than trusted).
func Validate(lang, content string) (checked bool, err error) {
	switch lang {
	case "go":
		_, err := parser.ParseFile(token.NewFileSet(), "fixed.go", content, parser.AllErrors)
		return true, err
	case "python":
		py, lerr := exec.LookPath("python3")
		if lerr != nil {
			return false, nil
		}
		cmd := exec.Command(py, "-I", "-c", "import ast,sys; ast.parse(sys.stdin.read())")
		cmd.Stdin = strings.NewReader(content)
		if out, err := cmd.CombinedOutput(); err != nil {
			return true, fmt.Errorf("python: %s", lastLine(string(out)))
		}
		return true, nil
	case "javascript":
		node, lerr := exec.LookPath("node")
		if lerr != nil {
			return false, nil
		}
		f, err := os.CreateTemp("", "secretscan-check-*.mjs")
		if err != nil {
			return false, nil
		}
		defer os.Remove(f.Name())
		f.WriteString(content)
		f.Close()
		if out, err := exec.Command(node, "--check", f.Name()).CombinedOutput(); err != nil {
			return true, fmt.Errorf("javascript: %s", lastLine(string(out)))
		}
		return true, nil
	}
	return false, nil
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return lines[len(lines)-1]
}

// Caveats are semantic notes about the env-lookup replacement per language.
var Caveats = map[string]string{
	"go":         `os.Getenv returns "" when the variable is unset; validate required values at startup`,
	"javascript": "process.env.X is undefined when unset; validate required values at startup",
	"typescript": "the replacement uses a non-null assertion (!); validate required values at startup",
	"python":     `os.environ["X"] raises KeyError at import time when unset (fail-fast)`,
	"java":       "System.getenv returns null when unset",
	"csharp":     "Environment.GetEnvironmentVariable returns null when unset",
	"ruby":       "ENV.fetch raises KeyError when unset (fail-fast)",
	"php":        "getenv returns false when unset",
	"shell":      `"${X:?}" aborts the script when X is unset (fail-fast)`,
}
