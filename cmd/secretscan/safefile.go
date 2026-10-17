// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
)

// Output files (reports, fix patches, hooks, --fix rewrites) are never
// written through an existing symlink or hard link: a link planted at an
// output path, for example in a branch checked out by CI, must not let
// secretscan truncate, rewrite or change the permissions of the file it
// points to. Content goes to a new temporary file in the destination
// directory (created exclusively, mode 0600) and is renamed over the path
// on Close. Rename replaces the directory entry itself, so it never follows
// a link, even one created after the checks below.

var errSymlinkOutput = errors.New("is a symbolic link; refusing to write through it (remove it or choose another path)")

// atomicFile is an output file that appears at its path only on Close.
type atomicFile struct {
	*os.File
	dst  string
	perm fs.FileMode
	// direct is set for an existing device or pipe (/dev/stdout, a FIFO):
	// those are written in place, never replaced or truncated.
	direct bool
	done   bool
}

// openAtomic prepares path for writing. Existing symlinks are refused unless
// replaceLink is set, in which case the link itself (never its target) is
// replaced by a regular file.
func openAtomic(path string, perm fs.FileMode, replaceLink bool) (*atomicFile, error) {
	if fi, err := os.Lstat(path); err == nil {
		m := fi.Mode()
		if m&fs.ModeSymlink != 0 {
			// /dev/stdout and /dev/fd/N are links to a terminal or pipe;
			// writing to those cannot damage a file.
			if t, err := os.Stat(path); err == nil && isStream(t.Mode()) {
				return openStream(path)
			}
			if !replaceLink {
				return nil, fmt.Errorf("%s %w", path, errSymlinkOutput)
			}
		}
		switch {
		case m&fs.ModeSymlink != 0:
		case m.IsDir():
			return nil, fmt.Errorf("%s is a directory", path)
		case isStream(m):
			return openStream(path)
		case !m.IsRegular():
			return nil, fmt.Errorf("%s is not a regular file", path)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	dir, base := filepath.Split(path)
	if dir == "" {
		dir = "."
	}
	tmp, err := os.CreateTemp(dir, "."+base+".secretscan-*")
	if err != nil {
		return nil, err
	}
	if err := tmp.Chmod(perm); err != nil && runtime.GOOS != "windows" {
		tmp.Close()
		os.Remove(tmp.Name())
		return nil, fmt.Errorf("cannot set permissions of %s: %w", path, err)
	}
	return &atomicFile{File: tmp, dst: path, perm: perm}, nil
}

func isStream(m fs.FileMode) bool {
	return m&(fs.ModeDevice|fs.ModeCharDevice|fs.ModeNamedPipe) != 0
}

// openStream opens an existing device or pipe for writing, without creating,
// truncating or changing anything, and re-checks what was opened in case the
// path was swapped for a regular file in between.
func openStream(path string) (*atomicFile, error) {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return nil, err
	}
	if fi, err := f.Stat(); err != nil || !isStream(fi.Mode()) {
		f.Close()
		return nil, fmt.Errorf("%s changed while it was being opened; not written", path)
	}
	return &atomicFile{File: f, dst: path, direct: true}, nil
}

// Close flushes the file and moves it into place.
func (a *atomicFile) Close() error {
	if a.done {
		return nil
	}
	a.done = true
	if a.direct {
		return a.File.Close()
	}
	tmp := a.File.Name()
	err := a.File.Sync()
	if cerr := a.File.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, a.dst)
	}
	if err != nil {
		os.Remove(tmp)
	}
	return err
}

// Abort discards the output, leaving any existing file at the path as it was.
func (a *atomicFile) Abort() {
	if a.done {
		return
	}
	a.done = true
	a.File.Close()
	if !a.direct {
		os.Remove(a.File.Name())
	}
}

// createPrivate opens secrets-bearing output (reports, fix patches) with mode
// 0600. Symlinks at the path are refused.
func createPrivate(path string) (*atomicFile, error) { return openAtomic(path, 0o600, false) }

func writePrivate(path string, b []byte) error { return writeAtomic(path, b, 0o600, false) }

func writeAtomic(path string, b []byte, perm fs.FileMode, replaceLink bool) error {
	f, err := openAtomic(path, perm, replaceLink)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Abort()
		return err
	}
	return f.Close()
}
