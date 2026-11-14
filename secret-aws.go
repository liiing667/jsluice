package jsluice

import (
	"regexp"
	"strings"
)

func awsMatcher() SecretMatcher {
	awsKey := regexp.MustCompile("^\\w+$")

	return SecretMatcher{"[(string) (template_string) (binary_expression)] @matches", func(n *Node) *Secret {
		// only evaluate the outermost string-like expression, so a
		// concatenated key is reported once rather than once per fragment
		if !n.IsOutermostStringy() {
			return nil
		}

		str := n.LiteralValue()

		// https://docs.aws.amazon.com/STS/latest/APIReference/API_Credentials.html
		if len(str) < 16 || len(str) > 128 {
			return nil
		}

		// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html
		prefixes := []string{
			"ABIA", "ACCA", "AGPA", "AIDA",
			"AIPA", "AKIA", "ANPA", "ANVA",
			"APKA", "AROA", "ASCA", "ASIA",
		}

		found := false
		for _, p := range prefixes {
			if strings.HasPrefix(str, p) {
				found = true
				break
			}
		}

		if !found {
			return nil
		}

		if strings.Contains(str, "_") {
			return nil
		}

		// Check it matches the regex
		if !awsKey.MatchString(str) {
			return nil
		}

		data := map[string]string{
			"key": str,
		}

		// We want to look in the same object for anything 'secret'.
		// Walk up to the enclosing pair/object, which may sit a couple of
		// levels above a concatenated or template string expression.
		enclosing := n.Parent()
		for enclosing != nil && enclosing.IsValid() && enclosing.Type() != "pair" {
			enclosing = enclosing.Parent()
		}

		if enclosing == nil || !enclosing.IsValid() {
			return &Secret{
				Kind:     "AWSAccessKey",
				Severity: SeverityLow,
				Data:     data,
			}
		}

		grandparent := enclosing.Parent()
		if grandparent == nil || grandparent.Type() != "object" {
			return &Secret{
				Kind:     "AWSAccessKey",
				Severity: SeverityLow,
				Data:     data,
			}
		}

		o := grandparent.AsObject()

		for _, k := range o.GetKeys() {
			k = strings.ToLower(k)
			if strings.Contains(k, "secret") {
				// TODO: check format of value
				// TODO: think of a way to handle multiple secrets in the same object?
				if node := o.GetNodeI(k); node != nil && node.IsValid() {
					data["secret"] = node.StringyValue()
					if data["secret"] == "" {
						data["secret"] = DecodeString(node.Content())
					}
				}
				break
			}
		}

		sev := SeverityLow
		if data["secret"] != "" {
			sev = SeverityHigh
		}
		return &Secret{
			Kind:     "AWSAccessKey",
			Severity: sev,
			Data:     data,
			Context:  o.AsMap(),
		}

	}}
}
