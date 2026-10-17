// SPDX-License-Identifier: Apache-2.0

// Command fingerprint prints a hash of secretscan's detection code: the
// non-test Go files of the detection packages, parsed and printed without
// comments, so a comment or formatting change does not count as a change
// in detection while any change to code, rules or regexes does.
//
//	go run ./bench/fingerprint [ROOT]
package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

var dirs = []string{"internal/detect", "internal/config", "internal/wordy", "internal/sources"}

func main() {
	root := "."
	if len(os.Args) > 1 {
		root = os.Args[1]
	}
	var files []string
	for _, d := range dirs {
		filepath.Walk(filepath.Join(root, d), func(p string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() && info.Name() == "gen" {
				return filepath.SkipDir
			}
			if !info.IsDir() && strings.HasSuffix(p, ".go") && !strings.HasSuffix(p, "_test.go") {
				files = append(files, p)
			}
			return nil
		})
	}
	sort.Strings(files)
	h := sha256.New()
	fset := token.NewFileSet()
	for _, p := range files {
		f, err := parser.ParseFile(fset, p, nil, 0) // no comments
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		var b bytes.Buffer
		if err := (&printer.Config{Mode: printer.RawFormat}).Fprint(&b, fset, f); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		rel, _ := filepath.Rel(root, p)
		fmt.Fprintf(h, "%s\x00%s\x00", filepath.ToSlash(rel), b.Bytes())
	}
	fmt.Printf("%x\n", h.Sum(nil)[:8])
}
