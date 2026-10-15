// SPDX-License-Identifier: Apache-2.0

// Package sources turns files, git history and diffs into fragments.
package sources

import (
	"bufio"
	"io"
	"regexp"
	"strconv"
	"strings"

	"github.com/AISolutionLabs/secret-scanner/internal/detect"
)

// CommitMarker prefixes commit header lines produced by GitLogFormat.
const CommitMarker = "\x00"

// GitLogFormat is the --format used for history scans.
const GitLogFormat = "--format=%x00%H%x1f%an%x1f%ae%x1f%aI%x1f%s"

var hunkRe = regexp.MustCompile(`^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@`)

// ParseDiff reads unified diff output (optionally interleaved with commit
// headers) and emits one fragment per contiguous block of added lines, with
// accurate new-file line numbers. Removed and context lines are not scanned.
// Hunk line counts are honored, so added lines that look like headers
// ("+++ ...") are handled correctly.
func ParseDiff(r io.Reader, maxBytes int64, emit func(detect.Fragment)) error {
	br := bufio.NewReaderSize(r, 1<<20)
	var (
		meta             detect.Fragment
		file             string
		oldLeft, newLeft int
		newLine          int
		block            strings.Builder
		blockStart       int
		blockNext        = -1
		fileBytes        int64
		skipFile         bool
	)
	flush := func() {
		if block.Len() > 0 && file != "" && !skipFile {
			f := meta
			f.FilePath = file
			f.Raw = block.String()
			f.StartLine = blockStart
			emit(f)
		}
		block.Reset()
		blockNext = -1
	}
	for {
		line, err := br.ReadString('\n')
		if line == "" && err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		line = strings.TrimSuffix(line, "\n")

		if oldLeft > 0 || newLeft > 0 {
			if line == "" {
				// Some tools strip the leading space of empty context lines.
				line = " "
			}
			switch line[0] {
			case '+':
				if blockNext != newLine {
					flush()
					blockStart = newLine
				}
				fileBytes += int64(len(line))
				if maxBytes > 0 && fileBytes > maxBytes {
					skipFile = true
				}
				block.WriteString(line[1:])
				block.WriteByte('\n')
				newLine++
				blockNext = newLine
				newLeft--
				continue
			case '-':
				oldLeft--
				continue
			case ' ':
				flush()
				oldLeft--
				newLeft--
				newLine++
				continue
			case '\\':
				continue // "\ No newline at end of file"
			}
			oldLeft, newLeft = 0, 0 // malformed hunk; resync on headers
		}

		switch {
		case strings.HasPrefix(line, CommitMarker):
			flush()
			parts := strings.SplitN(strings.TrimPrefix(line, CommitMarker), "\x1f", 5)
			meta = detect.Fragment{}
			if len(parts) == 5 {
				meta.Commit, meta.Author, meta.Email, meta.Date, meta.Message = parts[0], parts[1], parts[2], parts[3], parts[4]
			}
			file = ""
		case strings.HasPrefix(line, "diff --git "):
			flush()
			file = pathFromDiffGit(line)
			fileBytes, skipFile = 0, false
		case strings.HasPrefix(line, "+++ "):
			flush()
			p := strings.TrimRight(strings.TrimPrefix(line, "+++ "), "\t")
			if p == "/dev/null" {
				file = ""
				continue
			}
			file = cleanDiffPath(p)
		case strings.HasPrefix(line, "@@ "):
			flush()
			m := hunkRe.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			oldLeft = atoiDefault(m[2], 1)
			newLine = atoiDefault(m[3], 1)
			newLeft = atoiDefault(m[4], 1)
		}
	}
	flush()
	return nil
}

func atoiDefault(s string, def int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return n
}

func cleanDiffPath(p string) string {
	if strings.HasPrefix(p, `"`) {
		if u, err := strconv.Unquote(p); err == nil {
			p = u
		}
	}
	for _, pre := range []string{"b/", "w/", "i/"} {
		if strings.HasPrefix(p, pre) {
			return p[len(pre):]
		}
	}
	return p
}

func pathFromDiffGit(line string) string {
	rest := strings.TrimPrefix(line, "diff --git ")
	if i := strings.LastIndex(rest, " b/"); i >= 0 {
		return cleanDiffPath(rest[i+1:])
	}
	if i := strings.LastIndex(rest, ` "b/`); i >= 0 {
		return cleanDiffPath(rest[i+1:])
	}
	return ""
}
