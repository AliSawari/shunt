// Package rules implements proxification rule matching: applications,
// target hosts and target ports, processed top to bottom.
package rules

import (
	"net/netip"
	"os"
	"strconv"
	"strings"

	"shunt/internal/profile"
)

// Query describes one connection to be matched.
type Query struct {
	AppName string // executable file name, e.g. chrome.exe
	AppPath string // full path when known
	Host    string // target hostname when known
	IP      netip.Addr
	Port    uint16
}

type portRange struct{ lo, hi uint16 }

type target struct {
	kind   int // 0 wildcard host, 1 ip range, 2 prefix, 3 simple hostnames, 4 ip wildcard
	pat    string
	lo, hi netip.Addr
	pfx    netip.Prefix
}

type compiled struct {
	rule    *profile.Rule
	apps    []string
	targets []target
	ports   []portRange
	bad     bool // had filters but none parsed: never matches
}

// Matcher is an immutable compiled rule list.
type Matcher struct {
	rules []compiled
}

// ComputerName returns the local host name used for %ComputerName%.
func ComputerName() string {
	h, _ := os.Hostname()
	return strings.ToLower(h)
}

// SplitList splits a semicolon separated list honouring double quotes.
func SplitList(s string) []string {
	var out []string
	var cur strings.Builder
	inq := false
	flush := func() {
		t := strings.TrimSpace(cur.String())
		if t != "" {
			out = append(out, t)
		}
		cur.Reset()
	}
	for _, r := range s {
		switch {
		case r == '"':
			inq = !inq
		case (r == ';' || r == '\n' || r == '\r') && !inq:
			flush()
		default:
			cur.WriteRune(r)
		}
	}
	flush()
	return out
}

// Wildcard reports whether s matches pattern p, where '*' matches any run of
// characters and '?' matches a single character. Both must be lower-cased.
func Wildcard(p, s string) bool {
	pi, si, star, mark := 0, 0, -1, 0
	for si < len(s) {
		switch {
		case pi < len(p) && (p[pi] == '?' || p[pi] == s[si]):
			pi++
			si++
		case pi < len(p) && p[pi] == '*':
			star, mark = pi, si
			pi++
		case star >= 0:
			pi = star + 1
			mark++
			si = mark
		default:
			return false
		}
	}
	for pi < len(p) && p[pi] == '*' {
		pi++
	}
	return pi == len(p)
}

func parsePorts(s string) ([]portRange, bool) {
	var out []portRange
	for _, t := range SplitList(strings.ReplaceAll(s, ",", ";")) {
		lo, hi, isRange := strings.Cut(t, "-")
		a, err := strconv.ParseUint(strings.TrimSpace(lo), 10, 16)
		if err != nil {
			continue
		}
		b := a
		if isRange {
			if b, err = strconv.ParseUint(strings.TrimSpace(hi), 10, 16); err != nil {
				continue
			}
		}
		if b < a {
			a, b = b, a
		}
		out = append(out, portRange{uint16(a), uint16(b)})
	}
	return out, len(out) > 0
}

func isIPWildcard(s string) bool {
	if !strings.ContainsAny(s, "*?") {
		return false
	}
	for _, r := range s {
		if !(r >= '0' && r <= '9') && r != '.' && r != '*' && r != '?' {
			return false
		}
	}
	return strings.Contains(s, ".")
}

func parseTargets(s, computer string) []target {
	var out []target
	for _, t := range SplitList(s) {
		t = strings.ToLower(t)
		t = strings.ReplaceAll(t, "%computername%", computer)
		if t == "%simplehostnames%" {
			out = append(out, target{kind: 3})
			continue
		}
		if pfx, err := netip.ParsePrefix(t); err == nil {
			out = append(out, target{kind: 2, pfx: pfx.Masked()})
			continue
		}
		if lo, hi, ok := strings.Cut(t, "-"); ok {
			a, e1 := netip.ParseAddr(strings.TrimSpace(lo))
			b, e2 := netip.ParseAddr(strings.TrimSpace(hi))
			if e1 == nil && e2 == nil {
				out = append(out, target{kind: 1, lo: a.Unmap(), hi: b.Unmap()})
				continue
			}
		}
		if a, err := netip.ParseAddr(strings.Trim(t, "[]")); err == nil {
			a = a.Unmap()
			out = append(out, target{kind: 1, lo: a, hi: a})
			continue
		}
		if isIPWildcard(t) {
			out = append(out, target{kind: 4, pat: t})
			continue
		}
		out = append(out, target{kind: 0, pat: t})
	}
	return out
}

// Compile prepares a profile's rules for matching.
func Compile(p *profile.Profile) *Matcher {
	m := &Matcher{}
	computer := ComputerName()
	for i := range p.Rules {
		r := &p.Rules[i]
		c := compiled{rule: r}
		for _, a := range SplitList(r.Applications) {
			c.apps = append(c.apps, strings.ToLower(strings.ReplaceAll(a, "/", `\`)))
		}
		c.targets = parseTargets(r.Targets, computer)
		if strings.TrimSpace(r.Ports) != "" {
			var ok bool
			if c.ports, ok = parsePorts(r.Ports); !ok {
				c.bad = true
			}
		}
		m.rules = append(m.rules, c)
	}
	return m
}

func (c *compiled) matchApp(q *Query) bool {
	if len(c.apps) == 0 {
		return true
	}
	name := strings.ToLower(q.AppName)
	path := strings.ToLower(strings.ReplaceAll(q.AppPath, "/", `\`))
	for _, a := range c.apps {
		if strings.Contains(a, `\`) {
			if path != "" && Wildcard(a, path) {
				return true
			}
		} else if name != "" && Wildcard(a, name) {
			return true
		}
	}
	return false
}

func (t *target) match(host string, ip netip.Addr) bool {
	switch t.kind {
	case 0:
		return host != "" && Wildcard(t.pat, host)
	case 1:
		return ip.IsValid() && ip.BitLen() == t.lo.BitLen() && ip.Compare(t.lo) >= 0 && ip.Compare(t.hi) <= 0
	case 2:
		return ip.IsValid() && t.pfx.Contains(ip)
	case 3:
		return host != "" && !strings.Contains(host, ".")
	case 4:
		return ip.IsValid() && ip.Is4() && Wildcard(t.pat, ip.String())
	}
	return false
}

func (c *compiled) matchTarget(q *Query) bool {
	if len(c.targets) == 0 {
		return strings.TrimSpace(c.rule.Targets) == ""
	}
	host := strings.ToLower(strings.TrimSuffix(q.Host, "."))
	ip := q.IP.Unmap()
	for i := range c.targets {
		if c.targets[i].match(host, ip) {
			return true
		}
	}
	return false
}

func (c *compiled) matchPort(q *Query) bool {
	if len(c.ports) == 0 {
		return !c.bad
	}
	for _, p := range c.ports {
		if q.Port >= p.lo && q.Port <= p.hi {
			return true
		}
	}
	return false
}

// Match returns the index of the first enabled rule matching q, skipping any
// rule for which skip returns true. The Default (last) rule always matches.
func (m *Matcher) Match(q Query, skip func(*profile.Rule) bool) (int, *profile.Rule) {
	last := len(m.rules) - 1
	for i := range m.rules {
		c := &m.rules[i]
		if i == last {
			return i, c.rule
		}
		if !c.rule.Enabled || (skip != nil && skip(c.rule)) {
			continue
		}
		if c.matchApp(&q) && c.matchTarget(&q) && c.matchPort(&q) {
			return i, c.rule
		}
	}
	return -1, nil
}

// HostList is a compiled list of host patterns (used for DNS exclusions).
type HostList struct{ targets []target }

func CompileHostList(s string) *HostList {
	return &HostList{targets: parseTargets(s, ComputerName())}
}

func (h *HostList) Match(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	ip, _ := netip.ParseAddr(host)
	for i := range h.targets {
		if h.targets[i].match(host, ip) {
			return true
		}
	}
	return false
}
