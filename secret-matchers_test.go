package jsluice

import "testing"

func TestBuiltinSecretMatchersHandleLiteralSemantics(t *testing.T) {
	cases := []struct {
		name   string
		source string
		kind   string
		key    string
	}{
		{
			name:   "unicode escaped AWS key",
			source: `var a = "AKIA\u0049OSFODNN7EXAMPLE";`,
			kind:   "AWSAccessKey",
			key:    "AKIAIOSFODNN7EXAMPLE",
		},
		{
			name:   "concatenated AWS key",
			source: `var b = "AKIA" + "IOSFODNN7EXAMPLE";`,
			kind:   "AWSAccessKey",
			key:    "AKIAIOSFODNN7EXAMPLE",
		},
		{
			name:   "templated GCP key",
			source: "var c = `AIzaSyB47WKzDu9kkmFAsAYFlagkuJxdEXAMPLE`;",
			kind:   "gcpKey",
			key:    "AIzaSyB47WKzDu9kkmFAsAYFlagkuJxdEXAMPLE",
		},
		{
			name:   "escaped GitHub key",
			source: `var d = "ghp_\u0061bcdefghijklmnopqrstuvwxyz0123456789";`,
			kind:   "githubKey",
			key:    "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := NewAnalyzer([]byte(c.source))
			secrets := a.GetSecrets()

			if len(secrets) != 1 {
				t.Fatalf("want 1 secret; have %d (%v)", len(secrets), secrets)
			}

			s := secrets[0]

			if s.Kind != c.kind {
				t.Errorf("want kind %s; have %s", c.kind, s.Kind)
			}

			data, ok := s.Data.(map[string]string)
			if !ok {
				t.Fatalf("want map[string]string data; have %T", s.Data)
			}

			if data["key"] != c.key {
				t.Errorf("want key %q; have %q", c.key, data["key"])
			}

			if s.Line != 1 {
				t.Errorf("want line 1; have %d", s.Line)
			}

			if s.Column == 0 {
				t.Error("want a non-zero column")
			}

			if s.Source == "" {
				t.Error("want the original source snippet to be recorded")
			}
		})
	}
}

func TestConcatenatedSecretReportedOnce(t *testing.T) {
	// Each of the two string fragments would match the AWS regex on its own
	// prefix check; make sure only the outermost expression is reported.
	a := NewAnalyzer([]byte(`var b = "AKIA" + "IOSFODNN7EXAMPLE";`))
	secrets := a.GetSecrets()

	if len(secrets) != 1 {
		t.Fatalf("want exactly 1 secret; have %d", len(secrets))
	}

	if secrets[0].Source != `"AKIA" + "IOSFODNN7EXAMPLE"` {
		t.Errorf("want the full concatenation as source; have %q", secrets[0].Source)
	}
}

func TestSameNodeNotReportedTwiceForSameKind(t *testing.T) {
	a := NewAnalyzer([]byte(`var a = "AKIAIOSFODNN7EXAMPLE";`))

	a.AddSecretMatcher(SecretMatcher{
		Query: "[(string) (template_string) (binary_expression)] @matches",
		Fn: func(n *Node) *Secret {
			if n.Type() != "string" {
				return nil
			}
			return &Secret{Kind: "custom", Data: map[string]string{"match": n.DecodedString()}}
		},
	})

	a.AddSecretMatcher(SecretMatcher{
		Query: "[(string) (template_string) (binary_expression)] @matches",
		Fn: func(n *Node) *Secret {
			if n.Type() != "string" {
				return nil
			}
			return &Secret{Kind: "custom", Data: map[string]string{"match": n.DecodedString()}}
		},
	})

	secrets := a.GetSecrets()

	customCount := 0
	for _, s := range secrets {
		if s.Kind == "custom" {
			customCount++
		}
	}

	if customCount != 1 {
		t.Errorf("want 1 custom secret; have %d", customCount)
	}
}

func TestSecretLocation(t *testing.T) {
	source := []byte("var a = 1;\nvar b = \"AKIAIOSFODNN7EXAMPLE\";\n")
	a := NewAnalyzer(source)

	secrets := a.GetSecrets()
	if len(secrets) != 1 {
		t.Fatalf("want 1 secret; have %d", len(secrets))
	}

	s := secrets[0]

	if s.Line != 2 {
		t.Errorf("want line 2; have %d", s.Line)
	}

	if s.Column != 9 {
		t.Errorf("want column 9; have %d", s.Column)
	}

	if s.Source != `"AKIAIOSFODNN7EXAMPLE"` {
		t.Errorf("want original source; have %q", s.Source)
	}
}

func TestConcatenatedAWSKeyWithObjectContext(t *testing.T) {
	a := NewAnalyzer([]byte(`
		var config = {
			awsKey: "AKIA" + "IOSFODNN7EXAMPLE",
			awsSecret: "wJalr" + "XUTn"
		};
	`))

	secrets := a.GetSecrets()
	if len(secrets) != 1 {
		t.Fatalf("want 1 secret; have %d", len(secrets))
	}

	data := secrets[0].Data.(map[string]string)

	if data["key"] != "AKIAIOSFODNN7EXAMPLE" {
		t.Errorf("want joined key; have %q", data["key"])
	}

	if data["secret"] != "wJalrXUTn" {
		t.Errorf("want joined secret; have %q", data["secret"])
	}

	if secrets[0].Severity != SeverityHigh {
		t.Errorf("want high severity when a secret is present; have %s", secrets[0].Severity)
	}

	context := secrets[0].Context.(map[string]string)
	if context["awsKey"] != "AKIAIOSFODNN7EXAMPLE" {
		t.Errorf("want decoded context; have %q", context["awsKey"])
	}
}
