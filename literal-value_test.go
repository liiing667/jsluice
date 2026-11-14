package jsluice

import "testing"

// firstStringyNode returns the first string-like node found in a
// depth-first traversal of the parse tree.
func firstStringyNode(n *Node) *Node {
	if n == nil || !n.IsValid() {
		return nil
	}

	switch n.Type() {
	case "binary_expression", "template_string":
		return n
	}

	for i := 0; i < n.NamedChildCount(); i++ {
		if found := firstStringyNode(n.NamedChild(i)); found != nil {
			return found
		}
	}

	if n.Type() == "string" {
		return n
	}
	return nil
}

func TestLiteralValue(t *testing.T) {
	cases := []struct {
		name     string
		source   string
		expected string
	}{
		{
			name:     "plain string",
			source:   `"foo bar"`,
			expected: "foo bar",
		},
		{
			name:     "single quoted string with escapes",
			source:   `'AKIA\u0049OSFODNN7EXAMPLE'`,
			expected: "AKIAIOSFODNN7EXAMPLE",
		},
		{
			name:     "hex escape",
			source:   `"foo\x3dbar"`,
			expected: "foo=bar",
		},
		{
			name:     "string concatenation",
			source:   `"AKIA" + "IOSFODNN7EXAMPLE"`,
			expected: "AKIAIOSFODNN7EXAMPLE",
		},
		{
			name:     "three fragment concatenation",
			source:   `"token-" + "abc" + "-42"`,
			expected: "token-abc-42",
		},
		{
			name:     "concatenation with expression",
			source:   `"prefix-" + someVar + "-suffix"`,
			expected: "prefix-EXPR-suffix",
		},
		{
			name:     "template without substitutions",
			source:   "`AKIAIOSFODNN7EXAMPLE`",
			expected: "AKIAIOSFODNN7EXAMPLE",
		},
		{
			name:     "template with substitution",
			source:   "`AKIAIOSFODNN7${suffix}EXAMPLE`",
			expected: "AKIAIOSFODNN7EXPREXAMPLE",
		},
		{
			name:     "template with escaped characters",
			source:   "`foo\\x3dbar`",
			expected: "foo=bar",
		},
		{
			name:     "template leading substitution",
			source:   "`${\"lead\"}trail`",
			expected: "EXPRtrail",
		},
		{
			name:     "template trailing substitution",
			source:   "`head${x}`",
			expected: "headEXPR",
		},
		{
			name:     "template adjacent substitutions",
			source:   "`${x}${y}`",
			expected: "EXPREXPR",
		},
		{
			name:     "non concatenation operator",
			source:   `"a" - "b"`,
			expected: ExpressionPlaceholder,
		},
		{
			name:     "mixed concatenation and template",
			source:   "`AIza` + \"SyB47WKzDu9kkmFAsAYFlagkuJxdEXAMPLE\"",
			expected: "AIzaSyB47WKzDu9kkmFAsAYFlagkuJxdEXAMPLE",
		},
		{
			name:     "parenthesized concatenation",
			source:   `("AKIA" + "IOSFODNN7EXAMPLE")`,
			expected: "AKIAIOSFODNN7EXAMPLE",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := NewAnalyzer([]byte(c.source))

			got := firstStringyNode(a.RootNode()).LiteralValue()

			if got != c.expected {
				t.Errorf("want %q for LiteralValue(%s); have %q", c.expected, c.source, got)
			}
		})
	}
}

func TestStringyValue(t *testing.T) {
	a := NewAnalyzer([]byte(`var x = "AKIA" + "IOSFODNN7EXAMPLE";`))

	outer := firstStringyNode(a.RootNode())

	if outer == nil {
		t.Fatal("want an outermost stringy node; have nil")
	}

	if got := outer.StringyValue(); got != "AKIAIOSFODNN7EXAMPLE" {
		t.Errorf("want %q; have %q", "AKIAIOSFODNN7EXAMPLE", got)
	}

	if got := outer.Line(); got != 1 {
		t.Errorf("want line 1; have %d", got)
	}
}

func TestNodePosition(t *testing.T) {
	source := []byte("var a = 1;\nvar b = \"AKIAIOSFODNN7EXAMPLE\";\n")
	a := NewAnalyzer(source)

	var node *Node
	a.Query("(string) @matches", func(n *Node) {
		node = n
	})

	if node == nil {
		t.Fatal("want a string node; have nil")
	}

	if node.Line() != 2 {
		t.Errorf("want line 2; have %d", node.Line())
	}

	if node.Column() != 9 {
		t.Errorf("want column 9; have %d", node.Column())
	}
}
