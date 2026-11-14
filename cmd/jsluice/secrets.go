package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"sync"

	"github.com/BishopFox/jsluice"
)

// secretDedupe is shared by all workers so that identical content is only
// reported once, even when spread across multiple WARC records or files.
var secretDedupe = newSecretDeduper()

// secretDeduper keeps track of the secrets that have already been emitted
// so that identical content is only reported once, even when it appears in
// multiple input files or multiple records of a WARC file.
type secretDeduper struct {
	mu   sync.Mutex
	seen map[string]bool
}

func newSecretDeduper() *secretDeduper {
	return &secretDeduper{seen: make(map[string]bool)}
}

// Add records a secret and returns true if it had not been seen before.
func (d *secretDeduper) Add(s *jsluice.Secret) bool {
	if d == nil {
		return true
	}

	key := secretContentKey(s)

	d.mu.Lock()
	defer d.mu.Unlock()

	if d.seen[key] {
		return false
	}
	d.seen[key] = true
	return true
}

// secretContentKey builds a stable fingerprint of a secret's content.
// Filename and location metadata are deliberately excluded so that the
// same content found in different files or WARC records is treated as
// a duplicate.
func secretContentKey(s *jsluice.Secret) string {
	h := sha256.New()

	fmt.Fprintf(h, "kind=%s\n", s.Kind)
	fmt.Fprintf(h, "severity=%s\n", s.Severity)
	fmt.Fprintf(h, "data=%s\n", stableJSON(s.Data))
	fmt.Fprintf(h, "context=%s\n", stableJSON(s.Context))

	return hex.EncodeToString(h.Sum(nil))
}

// stableJSON serializes a value in a deterministic way so that it can
// be used as part of a dedup key.
func stableJSON(v any) string {
	b, err := json.Marshal(canonicalize(v))
	if err != nil {
		return fmt.Sprintf("%#v", v)
	}
	return string(b)
}

// canonicalize turns maps into sorted key/value representations, ensuring
// a stable serialization regardless of map iteration order.
func canonicalize(v any) any {
	switch val := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		out := make([][2]any, 0, len(keys))
		for _, k := range keys {
			out = append(out, [2]any{k, canonicalize(val[k])})
		}
		return out
	case map[string]string:
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		out := make([][2]string, 0, len(keys))
		for _, k := range keys {
			out = append(out, [2]string{k, val[k]})
		}
		return out
	case []any:
		out := make([]any, len(val))
		for i, item := range val {
			out[i] = canonicalize(item)
		}
		return out
	default:
		return v
	}
}

func extractSecrets(opts options, filename string, source []byte, output chan string, errs chan error) {
	analyzer := jsluice.NewAnalyzer(source)

	// TODO: come up with a nice way to cache the patterns file and
	// only throw any open or parse errors once
	if opts.patternsFile != "" {
		f, err := os.Open(opts.patternsFile)
		if err != nil {
			errs <- err
			return
		}

		patterns, err := jsluice.ParseUserPatterns(f)
		if err != nil {
			errs <- err
			return
		}

		analyzer.AddSecretMatchers(patterns.SecretMatchers())
	}

	matches := analyzer.GetSecrets()
	for _, match := range matches {

		match.Filename = filename

		// Deduplicate by content across files and WARC records
		if !secretDedupe.Add(match) {
			continue
		}

		j, err := json.Marshal(match)
		if err != nil {
			continue
		}
		output <- fmt.Sprintf("%s", j)
	}
}
