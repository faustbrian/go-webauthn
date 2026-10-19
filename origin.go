package webauthn

import (
	_ "embed"
	"net"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	identifier "github.com/faustbrian/go-identifier/v2"
)

// PSL source e1b8015c3b2f0f4f8c18659c2480fc1a22c07b20; the immutable full
// snapshot/checksum/license are documented in docs/protocol-sources.md.
//
//go:embed docs/public_suffix_list.dat
var pinnedPSL string

func validDomain(s string) bool {
	if len(s) == 0 || len(s) > 253 || s != strings.ToLower(s) || net.ParseIP(s) != nil {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, b := range []byte(label) {
			if !(b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '-') {
				return false
			}
		}
	}
	canonical, ok := asciiDomain(s)
	return ok && canonical == s
}

func asciiDomain(s string) (string, bool) {
	p, e := identifier.NewNormalizationProfile(identifier.NormalizationProfileSpec{ID: "webauthn-psl", Version: 1, Unicode: identifier.UnicodeNormalizationNone, IDNA: true, MaximumBytes: 253})
	if e != nil {
		return "", false
	}
	v, e := identifier.Normalize(identifier.Input(s), p)
	if e != nil {
		return "", false
	}
	return v.Record().Value, true
}

// The default prevailing PSL rule is '*'. Wildcards and exceptions are matched
// as domain labels, including private suffixes; suffix-lookalikes never match.
func publicSuffix(domain string) string {
	labels := strings.Split(domain, ".")
	best := labels[len(labels)-1]
	bestCount := 1
	for line := range strings.SplitSeq(pinnedPSL, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		prefix := ""
		if strings.HasPrefix(line, "!") {
			prefix = "!"
			line = line[1:]
		} else if strings.HasPrefix(line, "*.") {
			prefix = "*."
			line = line[2:]
		}
		// PSL stores U-labels; normalize rules with the committed fixed-Unicode
		// identifier owner so xn-- public suffixes cannot bypass this policy.
		if normalized, ok := asciiDomain(line); ok {
			line = normalized
		} else {
			continue
		}
		if prefix == "!" {
			rule := line
			if domain == rule || strings.HasSuffix(domain, "."+rule) {
				parts := strings.Split(rule, ".")
				return strings.Join(parts[1:], ".")
			}
			continue
		}
		if prefix == "*." {
			rule := line
			if strings.HasSuffix(domain, "."+rule) {
				n := strings.Count(rule, ".") + 2
				if n > bestCount && n <= len(labels) {
					bestCount = n
					best = strings.Join(labels[len(labels)-n:], ".")
				}
			}
			continue
		}
		if domain == line || strings.HasSuffix(domain, "."+line) {
			n := strings.Count(line, ".") + 1
			if n > bestCount {
				bestCount = n
				best = line
			}
		}
	}
	return best
}
func validOrigin(origin, rpid string, local bool) bool {
	if len(origin) == 0 || len(origin) > 2048 || !utf8.ValidString(origin) {
		return false
	}
	u, e := url.Parse(origin)
	if e != nil || u.User != nil || u.Opaque != "" || u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" || u.String() != origin {
		return false
	}
	host := u.Hostname()
	if host == "" || host != strings.ToLower(host) || strings.Contains(u.Host, "@") {
		return false
	}
	port := u.Port()
	canonicalHost := host
	if port != "" {
		n, e := strconv.Atoi(port)
		if e != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
			return false
		}
		// RFC6454 §6.2 omits default ports from browser origin serialization.
		// Reject unusable configuration instead of relaxing exact comparison.
		if u.Scheme == "https" && n == 443 || u.Scheme == "http" && n == 80 {
			return false
		}
		canonicalHost += ":" + port
	}
	if u.Host != canonicalHost {
		return false
	}
	if u.Scheme == "http" {
		return local && rpid == "localhost" && host == "localhost" && port != "" && u.Host == "localhost:"+port
	}
	if u.Scheme != "https" || !validDomain(host) || !validDomain(rpid) || rpid == publicSuffix(rpid) {
		return false
	}
	return host == rpid || strings.HasSuffix(host, "."+rpid)
}
