package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/slyrz/warc"
)

// writeTestWARC writes a WARC file containing the provided JavaScript
// body once per entry, each entry pretending to live at a different URL.
func writeTestWARC(t *testing.T, dir string, uris []string, js string) string {
	t.Helper()

	path := filepath.Join(dir, "test.warc")
	out, err := os.Create(path)
	if err != nil {
		t.Fatalf("failed to create WARC file: %s", err)
	}
	defer out.Close()

	writer := warc.NewWriter(out)

	for _, uri := range uris {
		header := warc.NewHeader()
		header.Set("WARC-Type", "response")
		header.Set("WARC-Target-URI", uri)
		header.Set("Content-Type", "application/http; msgtype=response")

		httpResponse := strings.Join([]string{
			"HTTP/1.1 200 OK",
			"Content-Type: application/javascript",
			"Content-Length: " + strconv.Itoa(len(js)),
			"",
			"",
		}, "\r\n") + js

		record := &warc.Record{
			Header:  header,
			Content: strings.NewReader(httpResponse),
		}

		if _, err := writer.WriteRecord(record); err != nil {
			t.Fatalf("failed to write WARC record: %s", err)
		}
	}

	return path
}

func TestReadWARCFile(t *testing.T) {
	js := "var a = \"AKIAIOSFODNN7EXAMPLE\";\n"
	uris := []string{
		"https://example.com/a.js",
		"https://example.com/b.js",
	}

	path := writeTestWARC(t, t.TempDir(), uris, js)

	responses, err := readWARCFile(path)
	if err != nil {
		t.Fatalf("readWARCFile returned an error: %s", err)
	}

	if len(responses) != 2 {
		t.Fatalf("want 2 responses; have %d", len(responses))
	}

	for i, response := range responses {
		if response.url != uris[i] {
			t.Errorf("want url %q; have %q", uris[i], response.url)
		}

		if string(response.source) != js {
			t.Errorf("want source %q; have %q", js, string(response.source))
		}
	}
}

func TestSecretsAreDeduplicatedAcrossWARCRecords(t *testing.T) {
	// The global deduper is shared between calls, so reset it for this test
	secretDedupe = newSecretDeduper()

	js := "var a = \"AKIA\\u0049OSFODNN7EXAMPLE\";\n"
	uris := []string{
		"https://example.com/a.js",
		"https://example.com/b.js",
		"https://example.com/c.js",
	}

	path := writeTestWARC(t, t.TempDir(), uris, js)

	responses, err := readWARCFile(path)
	if err != nil {
		t.Fatalf("readWARCFile returned an error: %s", err)
	}

	output := make(chan string, 16)
	errs := make(chan error, 16)

	for _, response := range responses {
		extractSecrets(options{}, response.url, response.source, output, errs)
	}
	close(output)
	close(errs)

	for err := range errs {
		if err != nil {
			t.Errorf("unexpected error: %s", err)
		}
	}

	count := 0
	for line := range output {
		if line != "" {
			count++
		}
	}

	if count != 1 {
		t.Errorf("want 1 deduplicated secret across 3 records; have %d", count)
	}
}
