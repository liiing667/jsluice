package jsluice

import (
	"strings"
	"testing"
)

// secretsByKind filters a slice of secrets down to those of the given kind.
func secretsByKind(secrets []*Secret, kind string) []*Secret {
	out := make([]*Secret, 0)
	for _, s := range secrets {
		if s.Kind == kind {
			out = append(out, s)
		}
	}
	return out
}

func TestParseUserPatterns(t *testing.T) {
	testData := strings.NewReader(`[
		{"name": "httpAuth", "value": "/[a-z0-9_/\\.:-]+@[a-z0-9-]+\\.[a-z0-9.-]+"},
		{"name": "base64", "value": "^(eyJ|YTo|Tzo|PD[89]|aHR0cHM6L|aHR0cDo|rO0)[%a-zA-Z0-9+/]+={0,2}"}
	]`)

	patterns, err := ParseUserPatterns(testData)

	if err != nil {
		t.Errorf("want nil error for ParseUserPatterns(testData); have %s", err)
	}

	if len(patterns) != 2 {
		t.Errorf("want 2 patterns from ParseUserPatterns(testData); have %d", len(patterns))
	}

	cases := []struct {
		i        int
		in       string
		expected bool
	}{
		{0, "//someuser:somepass@example.com", true},
		{0, "https://someuser:somepass@example.com", true},
		{0, "person@example.com", false},
		{1, "eyJmb28iOiAxMjN9Cg==", true},
		{1, "eyJ:-)b28iOiAxMjN9Cg==", false},
		{1, "foobareyJmb28iOiAxMjN9Cg==", false},
	}

	for _, c := range cases {
		if patterns[c.i].MatchValue(c.in) != c.expected {
			t.Errorf(
				"Want %t for (%s).MatchValue(%s); have %t",
				c.expected, patterns[c.i].reValue, c.in, !c.expected,
			)
		}
	}
}

func TestParseUserPatternsBadPattern(t *testing.T) {
	testData := strings.NewReader(`[
		{"name": "httpAuth", "pattern": "/[a-z0-9_/\\.:-]+@[a-z0-9-]+\\.[a-z0-9.-]+"},
		{"name": "base64", "pattern": "^(eyJ|YTo|Tzo|PD[89]|aHR0cHM6L|aHR0cDo|rO0[%a-zA-Z0-9+/]+={0,2}"}
	]`)

	_, err := ParseUserPatterns(testData)

	if err == nil {
		t.Error("want non-nil error for ParseUserPatterns(testData) with bad pattern; but have nil", err)
	}
}

func TestParseUserPatternsBadJSON(t *testing.T) {
	testData := strings.NewReader(`[
		{"name": "httpAuth", "pattern": "/[a-z0-9_/\\.:-]+@[a-z0-9-]+\\.[a-z0-9.-]+"},
		{"name": "base64", "pattern": "^(eyJ|YTo|Tzo|PD
	]`)

	_, err := ParseUserPatterns(testData)

	if err == nil {
		t.Error("want non-nil error for ParseUserPatterns(testData) with bad JSON; but have nil", err)
	}
}

func TestUserPatternStringMatcherLiteralSemantics(t *testing.T) {
	patterns, err := ParseUserPatterns(strings.NewReader(`[
		{"name": "awsLike", "value": "AKIA[0-9A-Z]{16}"}
	]`))
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	cases := []struct {
		name    string
		source  string
		match   string
		snippet string
	}{
		{
			name:    "escaped string",
			source:  `var a = "AKIA\u0049OSFODNN7EXAMPLE";`,
			match:   "AKIAIOSFODNN7EXAMPLE",
			snippet: `"AKIA\u0049OSFODNN7EXAMPLE"`,
		},
		{
			name:    "concatenated string",
			source:  `var b = "AKIA" + "IOSFODNN7EXAMPLE";`,
			match:   "AKIAIOSFODNN7EXAMPLE",
			snippet: `"AKIA" + "IOSFODNN7EXAMPLE"`,
		},
		{
			name:    "template string",
			source:  "var c = `AKIAIOSFODNN7EXAMPLE`;",
			match:   "AKIAIOSFODNN7EXAMPLE",
			snippet: "`AKIAIOSFODNN7EXAMPLE`",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := NewAnalyzer([]byte(c.source))
			a.AddSecretMatchers(patterns.SecretMatchers())

			secrets := secretsByKind(a.GetSecrets(), "awsLike")
			if len(secrets) != 1 {
				t.Fatalf("want 1 awsLike secret; have %d", len(secrets))
			}

			data := secrets[0].Data.(map[string]string)

			if data["match"] != c.match {
				t.Errorf("want match %q; have %q", c.match, data["match"])
			}

			if secrets[0].Source != c.snippet {
				t.Errorf("want source %q; have %q", c.snippet, secrets[0].Source)
			}

			if secrets[0].Line != 1 || secrets[0].Column == 0 {
				t.Errorf("want a 1-based line and column; have line=%d column=%d",
					secrets[0].Line, secrets[0].Column)
			}
		})
	}
}

func TestUserPatternPairMatcherLiteralSemantics(t *testing.T) {
	patterns, err := ParseUserPatterns(strings.NewReader(`[
		{"name": "token", "key": "secret", "value": "token-[a-z]+-\\d+"}
	]`))
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	a := NewAnalyzer([]byte(`
		var config = {
			secret: "token-" + "abc" + "-42"
		};
	`))
	a.AddSecretMatchers(patterns.SecretMatchers())

	secrets := secretsByKind(a.GetSecrets(), "token")
	if len(secrets) != 1 {
		t.Fatalf("want 1 token secret; have %d", len(secrets))
	}

	data := secrets[0].Data.(map[string]string)

	if data["value"] != "token-abc-42" {
		t.Errorf("want decoded value %q; have %q", "token-abc-42", data["value"])
	}

	if data["key"] != "secret" {
		t.Errorf("want key %q; have %q", "secret", data["key"])
	}

	if secrets[0].Source != `"token-" + "abc" + "-42"` {
		t.Errorf("want original source snippet; have %q", secrets[0].Source)
	}
}

func TestUserPatternObjectMatcherLiteralSemantics(t *testing.T) {
	patterns, err := ParseUserPatterns(strings.NewReader(`[
		{
			"name": "firebaseConfig",
			"object": [
				{"key": "apiKey", "value": "^AIza.+"},
				{"key": "authDomain"}
			]
		}
	]`))
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	a := NewAnalyzer([]byte(`
		var config = {
			apiKey: "AIza" + "SyB47WKzDu9kkmFAsAYFlagkuJxdEXAMPLE",
			authDomain: "example.firebaseapp.com"
		};
	`))
	a.AddSecretMatchers(patterns.SecretMatchers())

	secrets := secretsByKind(a.GetSecrets(), "firebaseConfig")
	if len(secrets) != 1 {
		t.Fatalf("want 1 firebaseConfig secret; have %d", len(secrets))
	}

	data := secrets[0].Data.(map[string]string)

	want := "AIzaSyB47WKzDu9kkmFAsAYFlagkuJxdEXAMPLE"
	if data["apiKey"] != want {
		t.Errorf("want apiKey %q; have %q", want, data["apiKey"])
	}
}

func TestUserPatternDoesNotMatchNonStringyValues(t *testing.T) {
	patterns, err := ParseUserPatterns(strings.NewReader(`[
		{"name": "token", "key": "secret", "value": ".+"}
	]`))
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	a := NewAnalyzer([]byte(`
		var config = {
			secret: 42
		};
	`))
	a.AddSecretMatchers(patterns.SecretMatchers())

	if secrets := a.GetSecrets(); len(secrets) != 0 {
		t.Errorf("want no secrets for a numeric value; have %d", len(secrets))
	}
}
