// Package signed implements exact-bytes Ed25519 tokens, the key registry,
// key generation, and key loading. A token signs the exact payload bytes
// behind a domain prefix, so a receiver verifies the bytes before parsing
// them and no canonicalization sits on the verification path. The handoff
// and the authorization context use different prefixes, so a signature for
// one can never verify as the other. Cryptography comes from the standard
// library only.
package signed

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"time"

	"citadel/internal/value"
)

// Domain prefixes.
const (
	PrefixHandoff = "citadel-handoff-v1\x00"
	PrefixAuthCtx = "citadel-authctx-v1\x00"
)

// Key roles.
const (
	RoleOrchestrator = "orchestrator"
	RoleAgent        = "agent"
)

// Key statuses.
const (
	StatusActive  = "active"
	StatusRevoked = "revoked"
)

// Wire is a signed token: the base64url payload bytes, the key ID, and the
// base64url signature over the prefix and the payload bytes.
type Wire struct {
	Payload string `json:"payload"`
	KID     string `json:"kid"`
	Sig     string `json:"sig"`
}

var b64 = base64.RawURLEncoding.Strict()

// Key is one registry entry.
type Key struct {
	KID       string    `json:"kid"`
	Agent     string    `json:"agent"`
	Role      string    `json:"role"`
	PublicKey string    `json:"public_key"` // base64url
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	Status    string    `json:"status"`
	pub       ed25519.PublicKey
}

// Pub returns the parsed public key.
func (k Key) Pub() ed25519.PublicKey { return k.pub }

// Registry is trusted configuration: loaded read-only at startup and
// distributed out of band. There is no fetching and no trust on first use.
type Registry struct {
	keys []Key
}

type registryFile struct {
	Keys []Key `json:"keys"`
}

// MaxRegistryBytes bounds the registry file.
const MaxRegistryBytes = 1 << 20

// ParseRegistry validates registry JSON.
func ParseRegistry(b []byte) (*Registry, error) {
	var f registryFile
	if err := value.DecodeStrict(b, &f, value.Limits{MaxBytes: MaxRegistryBytes}); err != nil {
		return nil, fmt.Errorf("%w: registry: %w", value.ErrConfig, err)
	}
	r := &Registry{}
	seen := map[string]bool{}
	for _, k := range f.Keys {
		raw, err := b64.DecodeString(k.PublicKey)
		switch {
		case err != nil || len(raw) != ed25519.PublicKeySize:
			return nil, fmt.Errorf("%w: registry key %q: bad public key", value.ErrConfig, k.KID)
		case k.KID == "" || len(k.KID) > 64 || seen[k.KID]:
			return nil, fmt.Errorf("%w: registry key ID %q missing, too long, or repeated", value.ErrConfig, k.KID)
		case k.Agent == "" || (k.Role != RoleOrchestrator && k.Role != RoleAgent):
			return nil, fmt.Errorf("%w: registry key %q: agent or role", value.ErrConfig, k.KID)
		case k.Status != StatusActive && k.Status != StatusRevoked:
			return nil, fmt.Errorf("%w: registry key %q: status %q", value.ErrConfig, k.KID, k.Status)
		case !k.NotAfter.After(k.NotBefore):
			return nil, fmt.Errorf("%w: registry key %q: empty validity window", value.ErrConfig, k.KID)
		}
		seen[k.KID] = true
		k.pub = ed25519.PublicKey(raw)
		r.keys = append(r.keys, k)
	}
	return r, nil
}

// LoadRegistry reads a registry file.
func LoadRegistry(path string) (*Registry, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: registry: %v", value.ErrConfig, err)
	}
	return ParseRegistry(b)
}

// NewKey builds a registry entry for a public key.
func NewKey(kid, agent, role string, pub ed25519.PublicKey, notBefore, notAfter time.Time, status string) Key {
	return Key{KID: kid, Agent: agent, Role: role, PublicKey: b64.EncodeToString(pub), NotBefore: notBefore.UTC(),
		NotAfter: notAfter.UTC(), Status: status, pub: slices.Clone(pub)}
}

// NewRegistry builds a registry from entries, validated as ParseRegistry
// validates a file.
func NewRegistry(keys ...Key) (*Registry, error) {
	b, err := json.Marshal(registryFile{Keys: keys})
	if err != nil {
		return nil, fmt.Errorf("registry: %w", err)
	}
	return ParseRegistry(b)
}

// Lookup returns kid's key if it is active and now is inside its validity
// window. An unknown, expired, not-yet-valid, or revoked key is refused.
func (r *Registry) Lookup(kid string, now time.Time) (Key, bool) {
	i := slices.IndexFunc(r.keys, func(k Key) bool { return k.KID == kid })
	if i < 0 {
		return Key{}, false
	}
	k := r.keys[i]
	if k.Status != StatusActive || now.Before(k.NotBefore) || !now.Before(k.NotAfter) {
		return Key{}, false
	}
	return k, true
}

// Keys returns a copy of the registry entries.
func (r *Registry) Keys() []Key { return slices.Clone(r.keys) }

// Marshal renders the registry as JSON.
func (r *Registry) Marshal() ([]byte, error) {
	return json.MarshalIndent(registryFile{Keys: r.keys}, "", "  ")
}

// Signer holds one private key.
type Signer struct {
	kid   string
	agent string
	priv  ed25519.PrivateKey
}

// NewSigner wraps a private key.
func NewSigner(kid, agent string, priv ed25519.PrivateKey) *Signer {
	return &Signer{kid: kid, agent: agent, priv: priv}
}

// KID returns the signer's key ID.
func (s *Signer) KID() string { return s.kid }

// Agent returns the signer's agent ID.
func (s *Signer) Agent() string { return s.agent }

// Sign signs prefix || payload.
func (s *Signer) Sign(prefix string, payload []byte) Wire {
	msg := make([]byte, 0, len(prefix)+len(payload))
	msg = append(append(msg, prefix...), payload...)
	return Wire{Payload: b64.EncodeToString(payload), KID: s.kid, Sig: b64.EncodeToString(ed25519.Sign(s.priv, msg))}
}

// Verify checks a token: the key is in the registry, active, inside its
// validity window, and of the required role; the base64 decodes strictly;
// and the signature covers the prefix and the exact payload bytes. Only
// then does it return the payload, unparsed.
func Verify(r *Registry, w Wire, prefix, role string, now time.Time) ([]byte, Key, error) {
	key, ok := r.Lookup(w.KID, now)
	if !ok {
		return nil, Key{}, fmt.Errorf("%w: %q", value.ErrUnknownKey, value.Truncate(w.KID))
	}
	if role != "" && key.Role != role {
		return nil, Key{}, fmt.Errorf("%w: key %s has role %s, need %s", value.ErrUnknownKey, key.KID, key.Role, role)
	}
	p, err := b64.DecodeString(w.Payload)
	if err != nil {
		return nil, Key{}, fmt.Errorf("%w: payload base64: %v", value.ErrSchema, err)
	}
	sig, err := b64.DecodeString(w.Sig)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, Key{}, fmt.Errorf("%w: signature base64", value.ErrSchema)
	}
	msg := make([]byte, 0, len(prefix)+len(p))
	msg = append(append(msg, prefix...), p...)
	if !ed25519.Verify(key.pub, msg, sig) {
		return nil, Key{}, fmt.Errorf("%w: key %s", value.ErrBadSig, key.KID)
	}
	return p, key, nil
}

// keyFile is the on-disk form of a private key.
type keyFile struct {
	KID        string `json:"kid"`
	Agent      string `json:"agent"`
	Role       string `json:"role"`
	PrivateKey string `json:"private_key"` // base64url seed
}

// LoadSigner reads a private key file. It refuses a file readable or
// writable by group or others.
func LoadSigner(path string) (*Signer, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("%w: key file: %v", value.ErrConfig, err)
	}
	if st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%w: %s has mode %04o; private keys must be 0600", value.ErrKeyPermissions, path, st.Mode().Perm())
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: key file: %v", value.ErrConfig, err)
	}
	var f keyFile
	if err := value.DecodeStrict(b, &f, value.Limits{MaxBytes: 4096}); err != nil {
		return nil, fmt.Errorf("%w: key file %s: %w", value.ErrConfig, path, err)
	}
	seed, err := b64.DecodeString(f.PrivateKey)
	if err != nil || len(seed) != ed25519.SeedSize || f.KID == "" || f.Agent == "" {
		return nil, fmt.Errorf("%w: key file %s: malformed", value.ErrConfig, path)
	}
	return NewSigner(f.KID, f.Agent, ed25519.NewKeyFromSeed(seed)), nil
}

// KeygenOptions configures Keygen.
type KeygenOptions struct {
	Dir       string    // where the private key file goes
	Registry  string    // registry.json to append the public key to
	Agent     string    // agent ID
	Role      string    // orchestrator or agent
	KID       string    // key ID; generated when empty
	NotBefore time.Time // validity window
	NotAfter  time.Time
	Rand      io.Reader // crypto/rand.Reader outside tests
}

// Keygen writes a private key file (mode 0600) and appends the public key to
// the registry, atomically. It returns the key ID.
func Keygen(o KeygenOptions) (string, error) {
	if o.Agent == "" || (o.Role != RoleOrchestrator && o.Role != RoleAgent) || !o.NotAfter.After(o.NotBefore) || o.Rand == nil {
		return "", fmt.Errorf("%w: keygen needs an agent, a role, a validity window, and a random source", value.ErrConfig)
	}
	pub, priv, err := ed25519.GenerateKey(o.Rand)
	if err != nil {
		return "", fmt.Errorf("keygen: %w", err)
	}
	kid := o.KID
	if kid == "" {
		var suffix [3]byte
		if _, err := io.ReadFull(o.Rand, suffix[:]); err != nil {
			return "", fmt.Errorf("keygen: %w", err)
		}
		kid = fmt.Sprintf("%s-%s-%s", o.Agent, o.NotBefore.UTC().Format("2006-01"), b64.EncodeToString(suffix[:]))
	}
	reg := &Registry{}
	if b, err := os.ReadFile(o.Registry); err == nil {
		if reg, err = ParseRegistry(b); err != nil {
			return "", err
		}
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("keygen: %w", err)
	}
	if _, dup := reg.find(kid); dup {
		return "", fmt.Errorf("%w: key ID %s already in the registry", value.ErrConfig, kid)
	}
	if err := os.MkdirAll(o.Dir, 0o700); err != nil {
		return "", fmt.Errorf("keygen: %w", err)
	}
	kb, _ := json.MarshalIndent(keyFile{KID: kid, Agent: o.Agent, Role: o.Role, PrivateKey: b64.EncodeToString(priv.Seed())}, "", "  ")
	if err := writeAtomic(filepath.Join(o.Dir, kid+".key"), kb, 0o600); err != nil {
		return "", err
	}
	reg.keys = append(reg.keys, Key{KID: kid, Agent: o.Agent, Role: o.Role, PublicKey: b64.EncodeToString(pub),
		NotBefore: o.NotBefore.UTC(), NotAfter: o.NotAfter.UTC(), Status: StatusActive, pub: pub})
	rb, err := reg.Marshal()
	if err != nil {
		return "", fmt.Errorf("keygen: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(o.Registry), 0o750); err != nil {
		return "", fmt.Errorf("keygen: %w", err)
	}
	return kid, writeAtomic(o.Registry, append(rb, '\n'), 0o644)
}

func (r *Registry) find(kid string) (Key, bool) {
	i := slices.IndexFunc(r.keys, func(k Key) bool { return k.KID == kid })
	if i < 0 {
		return Key{}, false
	}
	return r.keys[i], true
}

// Revoke marks kid revoked in the registry file. Rotation is: add a new key
// with an overlapping validity window, then revoke the old one.
func Revoke(registryPath, kid string) error {
	reg, err := LoadRegistry(registryPath)
	if err != nil {
		return err
	}
	i := slices.IndexFunc(reg.keys, func(k Key) bool { return k.KID == kid })
	if i < 0 {
		return fmt.Errorf("%w: no key %s", value.ErrConfig, kid)
	}
	reg.keys[i].Status = StatusRevoked
	rb, err := reg.Marshal()
	if err != nil {
		return err
	}
	return writeAtomic(registryPath, append(rb, '\n'), 0o644)
}

func writeAtomic(path string, b []byte, mode fs.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-"+filepath.Base(path))
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := os.Rename(name, path); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// DecodeWire strictly decodes a wire object of at most maxBytes.
func DecodeWire(body []byte, maxBytes int) (Wire, error) {
	var w Wire
	if len(body) > maxBytes {
		return Wire{}, fmt.Errorf("%w: %d bytes exceeds %d", value.ErrSize, len(body), maxBytes)
	}
	if err := value.DecodeStrict(body, &w, value.Limits{MaxBytes: maxBytes, MaxDepth: 2}); err != nil {
		return Wire{}, err
	}
	if w.Payload == "" || w.KID == "" || w.Sig == "" {
		return Wire{}, fmt.Errorf("%w: wire object needs payload, kid, and sig", value.ErrSchema)
	}
	return w, nil
}

// EncodeWire renders a wire object as JSON.
func EncodeWire(w Wire) []byte {
	b, _ := json.Marshal(w) // three strings always marshal
	return b
}

// EncodeBase64 encodes bytes the way tokens do.
func EncodeBase64(b []byte) string { return b64.EncodeToString(b) }
