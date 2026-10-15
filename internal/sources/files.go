package sources

import (
	"bytes"
	"context"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/anirudh/secretscan/internal/detect"
)

// FileOptions control filesystem scans.
type FileOptions struct {
	MaxBytes       int64
	FollowSymlinks bool
	Skip           func(relPath string) bool // allowlisted paths
}

// Stats counts what a source looked at.
type Stats struct {
	Files, Skipped int
	Bytes          int64
}

// Files walks each root (file or directory) and emits one fragment per text file.
func Files(ctx context.Context, roots []string, o FileOptions, emit func(detect.Fragment)) (Stats, error) {
	var st Stats
	for _, root := range roots {
		info, err := os.Stat(root)
		if err != nil {
			return st, err
		}
		if !info.IsDir() {
			scanFile(root, filepath.ToSlash(root), info, o, &st, emit)
			continue
		}
		err = filepath.WalkDir(root, func(p string, de fs.DirEntry, err error) error {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if err != nil {
				st.Skipped++
				return nil
			}
			rel, _ := filepath.Rel(root, p)
			rel = filepath.ToSlash(rel)
			if de.IsDir() {
				if de.Name() == ".git" && p != root {
					return filepath.SkipDir
				}
				if rel != "." && o.Skip != nil && o.Skip(rel+"/") {
					return filepath.SkipDir
				}
				return nil
			}
			if o.Skip != nil && o.Skip(rel) {
				st.Skipped++
				return nil
			}
			if de.Type()&fs.ModeSymlink != 0 {
				if !o.FollowSymlinks {
					st.Skipped++
					return nil
				}
			}
			fi, err := os.Stat(p) // follows symlinks
			if err != nil || !fi.Mode().IsRegular() {
				st.Skipped++
				return nil
			}
			scanFile(p, rel, fi, o, &st, emit)
			return nil
		})
		if err != nil {
			return st, err
		}
	}
	return st, nil
}

func scanFile(p, rel string, fi os.FileInfo, o FileOptions, st *Stats, emit func(detect.Fragment)) {
	if o.MaxBytes > 0 && fi.Size() > o.MaxBytes {
		st.Skipped++
		return
	}
	data, err := os.ReadFile(p)
	if err != nil || isBinary(data) {
		st.Skipped++
		return
	}
	st.Files++
	st.Bytes += int64(len(data))
	emit(detect.Fragment{Raw: string(data), FilePath: rel, StartLine: 1})
}

func isBinary(b []byte) bool {
	n := len(b)
	if n > 8000 {
		n = 8000
	}
	return bytes.IndexByte(b[:n], 0) >= 0
}

// Reader emits a single fragment for an io.Reader (stdin), or parses it as
// a unified diff when asDiff is set.
func Reader(r io.Reader, label string, asDiff bool, maxBytes int64, emit func(detect.Fragment)) error {
	if asDiff {
		return ParseDiff(r, maxBytes, emit)
	}
	lr := io.Reader(r)
	if maxBytes > 0 {
		lr = io.LimitReader(r, maxBytes)
	}
	data, err := io.ReadAll(lr)
	if err != nil {
		return err
	}
	if label == "" {
		label = "stdin"
	}
	emit(detect.Fragment{Raw: strings.ToValidUTF8(string(data), "�"), FilePath: label, StartLine: 1})
	return nil
}
