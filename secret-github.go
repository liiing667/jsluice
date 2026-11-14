package jsluice

import (
	"regexp"
)

func githubKeyMatcher() SecretMatcher {
	githubKey := regexp.MustCompile("([a-zA-Z0-9_-]{2,}:)?ghp_[a-zA-Z0-9]{30,}")

	return SecretMatcher{"[(string) (template_string) (binary_expression)] @matches", func(n *Node) *Secret {
		if !n.IsOutermostStringy() {
			return nil
		}

		str := n.LiteralValue()

		if !githubKey.MatchString(str) {
			return nil
		}

		data := map[string]string{
			"key": str,
		}

		match := &Secret{
			Kind:     "githubKey",
			Severity: SeverityLow,
			Data:     data,
		}

		// If the key is in an object we want to include that whole object
		// as context. The pair node may be above a concatenation or template
		// expression, so walk up until we find it.
		enclosing := n.Parent()
		for enclosing != nil && enclosing.IsValid() && enclosing.Type() != "pair" {
			enclosing = enclosing.Parent()
		}

		if enclosing == nil || !enclosing.IsValid() {
			return match
		}

		grandparent := enclosing.Parent()
		if grandparent == nil || grandparent.Type() != "object" {
			return match
		}

		match.Context = grandparent.AsObject().AsMap()

		return match
	}}
}
