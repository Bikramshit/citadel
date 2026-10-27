package value

import (
	"fmt"
	"net/netip"
	"time"
)

// MaxTextBytes bounds free-text values (processor reports, notes).
const MaxTextBytes = 8192

// ParseIPv4 parses s strictly: IPv4 only, no IPv6 or IPv4-mapped forms, no
// zones, no leading zeros, and the parsed address's String() must equal s.
// Nothing is normalized silently.
func ParseIPv4(s string) (netip.Addr, error) {
	if len(s) == 0 || len(s) > len("255.255.255.255") {
		return netip.Addr{}, fmt.Errorf("%w: ipv4 %q: bad length", ErrType, truncate(s))
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("%w: ipv4 %q: %v", ErrType, truncate(s), err)
	}
	if !a.Is4() || a.Zone() != "" {
		return netip.Addr{}, fmt.Errorf("%w: ipv4 %q: not an IPv4 address", ErrType, truncate(s))
	}
	if a.String() != s {
		return netip.Addr{}, fmt.Errorf("%w: ipv4 %q: not canonical", ErrType, truncate(s))
	}
	return a, nil
}

// ParseAccountID checks s against ^[a-z][a-z0-9-]{1,31}$.
func ParseAccountID(s string) (string, error) {
	if len(s) < 2 || len(s) > 32 {
		return "", fmt.Errorf("%w: account id %q: bad length", ErrType, truncate(s))
	}
	if s[0] < 'a' || s[0] > 'z' {
		return "", fmt.Errorf("%w: account id %q: must start with a-z", ErrType, truncate(s))
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return "", fmt.Errorf("%w: account id %q: bad character", ErrType, truncate(s))
		}
	}
	return s, nil
}

// HostSet reports whether a host name exists in the inventory.
type HostSet interface {
	HostExists(name string) bool
}

// ParseHostname checks that s is a lowercase RFC 1123 label and, when known is
// not nil, that the inventory lists it. Host names come from the inventory.
func ParseHostname(s string, known HostSet) (string, error) {
	if len(s) == 0 || len(s) > 63 {
		return "", fmt.Errorf("%w: hostname %q: bad length", ErrType, truncate(s))
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		alnum := c >= 'a' && c <= 'z' || c >= '0' && c <= '9'
		if !alnum && !(c == '-' && i > 0 && i < len(s)-1) {
			return "", fmt.Errorf("%w: hostname %q: bad character", ErrType, truncate(s))
		}
	}
	if known != nil && !known.HostExists(s) {
		return "", fmt.Errorf("%w: hostname %q: not in inventory", ErrType, truncate(s))
	}
	return s, nil
}

// ParseDuration parses a positive duration written as hours, minutes, and
// seconds in that order, each at most once, with integer counts: "1h",
// "30m", "1h30m". Fractions, signs, and other units are rejected.
func ParseDuration(s string) (time.Duration, error) {
	if len(s) == 0 || len(s) > 16 {
		return 0, fmt.Errorf("%w: duration %q: bad length", ErrType, truncate(s))
	}
	units := []struct {
		c byte
		d time.Duration
	}{{'h', time.Hour}, {'m', time.Minute}, {'s', time.Second}}
	var total time.Duration
	i, u := 0, 0
	for i < len(s) {
		j := i
		for j < len(s) && s[j] >= '0' && s[j] <= '9' {
			j++
		}
		if j == i || j-i > 6 || j == len(s) {
			return 0, fmt.Errorf("%w: duration %q: malformed", ErrType, truncate(s))
		}
		n := 0
		for _, c := range s[i:j] {
			n = n*10 + int(c-'0')
		}
		for u < len(units) && units[u].c != s[j] {
			u++
		}
		if u == len(units) {
			return 0, fmt.Errorf("%w: duration %q: unit order or unit", ErrType, truncate(s))
		}
		total += time.Duration(n) * units[u].d
		u++
		i = j + 1
	}
	if total <= 0 {
		return 0, fmt.Errorf("%w: duration %q: must be positive", ErrType, truncate(s))
	}
	return total, nil
}

// FormatDuration writes d in the form ParseDuration accepts, so the two round
// trip.
func FormatDuration(d time.Duration) string {
	if d <= 0 {
		return "0s"
	}
	var out []byte
	h := d / time.Hour
	d -= h * time.Hour
	m := d / time.Minute
	d -= m * time.Minute
	s := d / time.Second
	if h > 0 {
		out = fmt.Appendf(out, "%dh", h)
	}
	if m > 0 {
		out = fmt.Appendf(out, "%dm", m)
	}
	if s > 0 || len(out) == 0 {
		out = fmt.Appendf(out, "%ds", s)
	}
	return string(out)
}

// ParseText checks a free-text value: valid UTF-8 within MaxTextBytes.
func ParseText(s string, maxBytes int) (string, error) {
	if maxBytes <= 0 {
		maxBytes = MaxTextBytes
	}
	if len(s) > maxBytes {
		return "", fmt.Errorf("%w: text longer than %d bytes", ErrType, maxBytes)
	}
	if !validUTF8(s) {
		return "", fmt.Errorf("%w: text is not valid UTF-8", ErrType)
	}
	return s, nil
}

// truncate shortens attacker-controlled text before it enters an error
// message, and escapes nothing itself: callers format it with %q.
func truncate(s string) string {
	const limit = 64
	if len(s) <= limit {
		return s
	}
	return s[:limit] + "..."
}

// Truncate is truncate for other packages that log attacker-controlled text;
// format the result with %q so it is escaped.
func Truncate(s string) string { return truncate(s) }
