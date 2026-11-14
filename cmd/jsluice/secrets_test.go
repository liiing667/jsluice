package main

import (
	"testing"

	"github.com/BishopFox/jsluice"
)

func TestSecretDeduper(t *testing.T) {
	d := newSecretDeduper()

	first := &jsluice.Secret{
		Kind:     "AWSAccessKey",
		Severity: jsluice.SeverityLow,
		Data:     map[string]string{"key": "AKIAIOSFODNN7EXAMPLE"},
	}

	second := &jsluice.Secret{
		Kind:     "AWSAccessKey",
		Severity: jsluice.SeverityLow,
		Data:     map[string]string{"key": "AKIAIOSFODNN7EXAMPLE"},
		// location and filename differ, but content is the same
		Filename: "https://example.com/other.js",
		Line:     42,
		Column:   7,
		Source:   `"AKIAIOSFODNN7EXAMPLE"`,
	}

	if !d.Add(first) {
		t.Error("want the first secret to be accepted")
	}

	if d.Add(second) {
		t.Error("want identical content in another file to be treated as a duplicate")
	}

	different := &jsluice.Secret{
		Kind:     "AWSAccessKey",
		Severity: jsluice.SeverityLow,
		Data:     map[string]string{"key": "AKIAIOSFODNN7OTHER00"},
	}

	if !d.Add(different) {
		t.Error("want different content to be accepted")
	}
}

func TestSecretDeduperKeepsDifferentKinds(t *testing.T) {
	d := newSecretDeduper()

	first := &jsluice.Secret{
		Kind: "customOne",
		Data: map[string]string{"match": "same-value"},
	}

	second := &jsluice.Secret{
		Kind: "customTwo",
		Data: map[string]string{"match": "same-value"},
	}

	if !d.Add(first) {
		t.Error("want the first secret to be accepted")
	}

	if !d.Add(second) {
		t.Error("want secrets of different kinds to be reported separately")
	}
}

func TestSecretContentKeyIgnoresLocation(t *testing.T) {
	first := &jsluice.Secret{
		Kind:     "AWSAccessKey",
		Severity: jsluice.SeverityLow,
		Data:     map[string]string{"key": "AKIAIOSFODNN7EXAMPLE"},
		Filename: "a.js",
		Line:     1,
		Column:   9,
	}

	second := &jsluice.Secret{
		Kind:     "AWSAccessKey",
		Severity: jsluice.SeverityLow,
		Data:     map[string]string{"key": "AKIAIOSFODNN7EXAMPLE"},
		Filename: "b.js",
		Line:     99,
		Column:   3,
	}

	if secretContentKey(first) != secretContentKey(second) {
		t.Error("want location and filename to be excluded from the content key")
	}
}

func TestStableJSONIsOrderIndependent(t *testing.T) {
	first := map[string]string{"a": "1", "b": "2"}
	second := map[string]string{"b": "2", "a": "1"}

	if stableJSON(first) != stableJSON(second) {
		t.Error("want stableJSON to be independent of map iteration order")
	}
}
