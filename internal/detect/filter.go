package detect

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/anirudh/secretscan/internal/config"
)

// IgnoreSet suppresses known findings. It understands:
//   - gitleaks fingerprints: [commit:]file:rule:line
//   - sha256:<hex> of a secret (survives line moves and file renames)
//   - rule:<id>  or  rule:<id>:<file>  (suppress a rule globally or for one file)
type IgnoreSet struct {
	fingerprints map[string]bool
	hashes       map[string]bool
	rules        map[string]bool
	ruleFiles    map[string]bool
}

// NewIgnoreSet returns an empty set.
func NewIgnoreSet() *IgnoreSet {
	return &IgnoreSet{fingerprints: map[string]bool{}, hashes: map[string]bool{}, rules: map[string]bool{}, ruleFiles: map[string]bool{}}
}

// LoadIgnoreFile adds entries from an ignore file (.secretscanignore or
// .gitleaksignore). Missing files are not an error.
func (s *IgnoreSet) LoadIgnoreFile(path string) error {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if i := strings.Index(line, " #"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		s.Add(line)
	}
	return sc.Err()
}

// Add inserts one entry.
func (s *IgnoreSet) Add(entry string) {
	switch {
	case strings.HasPrefix(entry, "sha256:"):
		s.hashes[strings.ToLower(strings.TrimPrefix(entry, "sha256:"))] = true
	case strings.HasPrefix(entry, "rule:"):
		rest := strings.TrimPrefix(entry, "rule:")
		if id, file, ok := strings.Cut(rest, ":"); ok {
			s.ruleFiles[id+"\x00"+file] = true
		} else {
			s.rules[rest] = true
		}
	default:
		s.fingerprints[entry] = true
	}
}

// LoadBaseline adds every finding from a previous JSON report.
func (s *IgnoreSet) LoadBaseline(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("baseline: %w", err)
	}
	var fs []Finding
	if err := json.Unmarshal(data, &fs); err != nil {
		return fmt.Errorf("baseline %s: expected a JSON report: %w", path, err)
	}
	for _, f := range fs {
		if f.SecretHash != "" {
			s.ruleFiles["\x01"+f.RuleID+"\x00"+f.File+"\x00"+f.SecretHash] = true
		}
		if f.Fingerprint != "" {
			s.fingerprints[f.Fingerprint] = true
		}
	}
	return nil
}

// Ignored reports whether a finding is suppressed.
func (s *IgnoreSet) Ignored(f Finding) bool {
	if s == nil {
		return false
	}
	return s.fingerprints[f.Fingerprint] ||
		s.fingerprints[fmt.Sprintf("%s:%s:%d", f.File, f.RuleID, f.StartLine)] ||
		s.hashes[f.SecretHash] ||
		s.rules[f.RuleID] ||
		s.ruleFiles[f.RuleID+"\x00"+f.File] ||
		s.ruleFiles["\x01"+f.RuleID+"\x00"+f.File+"\x00"+f.SecretHash]
}

// MeetsSeverity reports whether f is at or above min.
func MeetsSeverity(f Finding, min string) bool {
	return config.SeverityRank(f.Severity) >= config.SeverityRank(min)
}
