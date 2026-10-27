package value

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

// Limits bound what DecodeStrict accepts. Zero fields take the defaults
// noted on each.
type Limits struct {
	MaxBytes       int  // whole input; default 64 KiB
	MaxDepth       int  // nesting of objects and arrays; default 32
	MaxStringBytes int  // any single string, key or value; default 16 KiB
	MaxArrayLen    int  // any single array; default 4096
	AnyKeyCase     bool // allow object keys outside [a-z0-9_]; duplicates are still refused case-insensitively
}

func (l Limits) withDefaults() Limits {
	if l.MaxBytes == 0 {
		l.MaxBytes = 64 << 10
	}
	if l.MaxDepth == 0 {
		l.MaxDepth = 32
	}
	if l.MaxStringBytes == 0 {
		l.MaxStringBytes = 16 << 10
	}
	if l.MaxArrayLen == 0 {
		l.MaxArrayLen = 4096
	}
	return l
}

// DecodeStrict decodes exactly one JSON value from data into v. It refuses
// inputs over the size limit (ERR_SIZE) and, as ERR_SCHEMA, invalid UTF-8,
// duplicate object keys (exact or case-insensitive, which encoding/json would
// otherwise merge, keeping the last), keys outside [a-z0-9_] unless allowed,
// unknown struct fields, trailing data, and limit violations.
//
// The token-level pre-pass runs before encoding/json sees the input, because
// encoding/json keeps the last duplicate key silently and matches keys
// case-insensitively.
func DecodeStrict(data []byte, v any, lim Limits) error {
	lim = lim.withDefaults()
	if len(data) > lim.MaxBytes {
		return fmt.Errorf("%w: %d bytes exceeds %d", ErrSize, len(data), lim.MaxBytes)
	}
	if err := prepass(data, lim); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%w: %v", ErrSchema, err)
	}
	return nil
}

type frame struct {
	object    bool
	expectKey bool
	keys      map[string]bool // exact keys
	folded    map[string]bool // case-folded keys
	n         int             // array length so far
}

func prepass(data []byte, lim Limits) error {
	if !utf8.Valid(data) {
		return fmt.Errorf("%w: invalid UTF-8", ErrSchema)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var stack []*frame
	done := false // one complete top-level value seen
	// completed records that a value finished inside the top frame.
	completed := func() error {
		if len(stack) == 0 {
			done = true
			return nil
		}
		top := stack[len(stack)-1]
		if top.object {
			top.expectKey = true
			return nil
		}
		top.n++
		if top.n > lim.MaxArrayLen {
			return fmt.Errorf("%w: array longer than %d", ErrSchema, lim.MaxArrayLen)
		}
		return nil
	}
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			if !done {
				return fmt.Errorf("%w: empty or truncated input", ErrSchema)
			}
			return nil
		}
		if err != nil {
			return fmt.Errorf("%w: %v", ErrSchema, err)
		}
		if done {
			return fmt.Errorf("%w: more than one top-level value", ErrSchema)
		}
		var top *frame
		if len(stack) > 0 {
			top = stack[len(stack)-1]
		}
		if top != nil && top.object && top.expectKey {
			if d, ok := tok.(json.Delim); ok && d == '}' {
				stack = stack[:len(stack)-1]
				if err := completed(); err != nil {
					return err
				}
				continue
			}
			key, ok := tok.(string)
			if !ok {
				return fmt.Errorf("%w: object key is not a string", ErrSchema)
			}
			if err := checkKey(key, top, lim); err != nil {
				return err
			}
			top.expectKey = false
			continue
		}
		switch t := tok.(type) {
		case json.Delim:
			switch t {
			case '{', '[':
				if len(stack) >= lim.MaxDepth {
					return fmt.Errorf("%w: nesting deeper than %d", ErrSchema, lim.MaxDepth)
				}
				f := &frame{object: t == '{', expectKey: t == '{'}
				if f.object {
					f.keys, f.folded = map[string]bool{}, map[string]bool{}
				}
				stack = append(stack, f)
			case ']':
				stack = stack[:len(stack)-1]
				if err := completed(); err != nil {
					return err
				}
			default:
				return fmt.Errorf("%w: unexpected %v", ErrSchema, t)
			}
		case string:
			if len(t) > lim.MaxStringBytes {
				return fmt.Errorf("%w: string longer than %d bytes", ErrSchema, lim.MaxStringBytes)
			}
			if err := completed(); err != nil {
				return err
			}
		default: // number, bool, null
			if err := completed(); err != nil {
				return err
			}
		}
	}
}

func checkKey(key string, f *frame, lim Limits) error {
	if len(key) == 0 || len(key) > lim.MaxStringBytes || len(key) > 256 {
		return fmt.Errorf("%w: bad object key length", ErrSchema)
	}
	if !lim.AnyKeyCase {
		for i := 0; i < len(key); i++ {
			c := key[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
				return fmt.Errorf("%w: object key %q has a character outside [a-z0-9_]", ErrSchema, truncate(key))
			}
		}
	}
	if f.keys[key] {
		return fmt.Errorf("%w: duplicate key %q", ErrSchema, truncate(key))
	}
	folded := foldKey(key)
	if f.folded[folded] {
		return fmt.Errorf("%w: key %q duplicates another key case-insensitively", ErrSchema, truncate(key))
	}
	f.keys[key], f.folded[folded] = true, true
	return nil
}

// foldKey folds a key the way encoding/json may match it to a field: simple
// Unicode case folding, which also maps the Kelvin sign to k and the long s
// to s.
func foldKey(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case 'K': // Kelvin sign
			r = 'k'
		case 'ſ': // long s
			r = 's'
		}
		b.WriteString(strings.ToLower(string(r)))
	}
	return b.String()
}

func validUTF8(s string) bool { return utf8.ValidString(s) }
