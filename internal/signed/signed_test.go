package signed

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"citadel/internal/value"
)

var t0 = time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)

type envelopeVector struct {
	SeedHex   string `json:"seed_hex"`
	KID       string `json:"kid"`
	Agent     string `json:"agent"`
	Role      string `json:"role"`
	Prefix    string `json:"prefix"`
	PublicKey string `json:"public_key"`
	Payload   string `json:"payload"`
	Sig       string `json:"sig"`
	Wire      string `json:"wire"`
}

// Golden vectors from an independent Ed25519 implementation: signing the
// prefix and the exact payload bytes with the fixed test keys gives these
// signatures and wire objects, and they verify.
func TestSignedEnvelopeGoldenVectors(t *testing.T) {
	b, err := os.ReadFile("../../testdata/vectors/signed_envelopes.json")
	if err != nil {
		t.Fatal(err)
	}
	var vs []envelopeVector
	if err := json.Unmarshal(b, &vs); err != nil || len(vs) == 0 {
		t.Fatal(err)
	}
	for _, v := range vs {
		seed, _ := hex.DecodeString(v.SeedHex)
		priv := ed25519.NewKeyFromSeed(seed)
		s := NewSigner(v.KID, v.Agent, priv)
		w := s.Sign(v.Prefix, []byte(v.Payload))
		if w.Sig != v.Sig || string(EncodeWire(w)) != v.Wire {
			t.Errorf("%s: signature or wire differs", v.KID)
		}
		if EncodeBase64(priv.Public().(ed25519.PublicKey)) != v.PublicKey {
			t.Errorf("%s: public key differs", v.KID)
		}
		reg, err := NewRegistry(NewKey(v.KID, v.Agent, v.Role, priv.Public().(ed25519.PublicKey), t0.Add(-time.Hour), t0.Add(time.Hour), StatusActive))
		if err != nil {
			t.Fatal(err)
		}
		w2, err := DecodeWire([]byte(v.Wire), 1<<16)
		if err != nil {
			t.Fatal(err)
		}
		p, key, err := Verify(reg, w2, v.Prefix, v.Role, t0)
		if err != nil || string(p) != v.Payload || key.Agent != v.Agent {
			t.Errorf("%s: verify: %v", v.KID, err)
		}
		other := PrefixHandoff
		if v.Prefix == PrefixHandoff {
			other = PrefixAuthCtx
		}
		if _, _, err := Verify(reg, w2, other, "", t0); !errors.Is(err, value.ErrBadSig) {
			t.Errorf("%s: verified under the other domain prefix", v.KID)
		}
	}
}

func TestRegistryLookupWindowsAndRevocation(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	reg, err := NewRegistry(
		NewKey("a", "investigator", RoleAgent, pub, t0, t0.Add(time.Hour), StatusActive),
		NewKey("r", "investigator", RoleAgent, pub, t0, t0.Add(time.Hour), StatusRevoked),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := reg.Lookup("a", t0.Add(time.Minute)); !ok {
		t.Fatal("active key")
	}
	for _, c := range []struct {
		kid string
		at  time.Time
	}{{"a", t0.Add(-time.Second)}, {"a", t0.Add(time.Hour)}, {"r", t0.Add(time.Minute)}, {"zz", t0}} {
		if _, ok := reg.Lookup(c.kid, c.at); ok {
			t.Errorf("%s at %s accepted", c.kid, c.at)
		}
	}
	if len(reg.Keys()) != 2 {
		t.Fatal("Keys")
	}
	bad := []string{
		`{"keys":[{"kid":"a","agent":"x","role":"agent","public_key":"AA","not_before":"2026-01-01T00:00:00Z","not_after":"2027-01-01T00:00:00Z","status":"active"}]}`,
		`{"keys":[{"kid":"","agent":"x","role":"agent","public_key":"` + EncodeBase64(pub) + `","not_before":"2026-01-01T00:00:00Z","not_after":"2027-01-01T00:00:00Z","status":"active"}]}`,
		`{"keys":[{"kid":"a","agent":"x","role":"admin","public_key":"` + EncodeBase64(pub) + `","not_before":"2026-01-01T00:00:00Z","not_after":"2027-01-01T00:00:00Z","status":"active"}]}`,
		`{"keys":[{"kid":"a","agent":"x","role":"agent","public_key":"` + EncodeBase64(pub) + `","not_before":"2026-01-01T00:00:00Z","not_after":"2027-01-01T00:00:00Z","status":"maybe"}]}`,
		`{"keys":[{"kid":"a","agent":"x","role":"agent","public_key":"` + EncodeBase64(pub) + `","not_before":"2027-01-01T00:00:00Z","not_after":"2026-01-01T00:00:00Z","status":"active"}]}`,
		`{"keys":[],"extra":1}`,
	}
	for i, s := range bad {
		if _, err := ParseRegistry([]byte(s)); !errors.Is(err, value.ErrConfig) {
			t.Errorf("bad registry %d accepted", i)
		}
	}
	dup := NewKey("a", "x", RoleAgent, pub, t0, t0.Add(time.Hour), StatusActive)
	if _, err := NewRegistry(dup, dup); !errors.Is(err, value.ErrConfig) {
		t.Fatal("duplicate key ID")
	}
}

func TestVerifyErrors(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	reg, _ := NewRegistry(NewKey("k", "investigator", RoleAgent, pub, t0, t0.Add(time.Hour), StatusActive))
	s := NewSigner("k", "investigator", priv)
	w := s.Sign(PrefixHandoff, []byte("payload"))
	if _, _, err := Verify(reg, w, PrefixHandoff, RoleOrchestrator, t0); !errors.Is(err, value.ErrUnknownKey) {
		t.Fatal("wrong role")
	}
	bad := w
	bad.Payload += "!"
	if _, _, err := Verify(reg, bad, PrefixHandoff, "", t0); !errors.Is(err, value.ErrSchema) {
		t.Fatal("bad payload base64")
	}
	bad = w
	bad.Sig = "AAAA"
	if _, _, err := Verify(reg, bad, PrefixHandoff, "", t0); !errors.Is(err, value.ErrSchema) {
		t.Fatal("short signature")
	}
	if _, err := DecodeWire(bytes.Repeat([]byte("a"), 100), 10); !errors.Is(err, value.ErrSize) {
		t.Fatal("size")
	}
	if s.KID() != "k" || s.Agent() != "investigator" {
		t.Fatal("accessors")
	}
}

func TestKeygenLoadRotateRevoke(t *testing.T) {
	dir := t.TempDir()
	regPath := filepath.Join(dir, "registry.json")
	kid, err := Keygen(KeygenOptions{Dir: filepath.Join(dir, "keys"), Registry: regPath, Agent: "investigator", Role: RoleAgent,
		NotBefore: t0, NotAfter: t0.Add(30 * 24 * time.Hour), Rand: rand.Reader})
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "keys", kid+".key")
	st, err := os.Stat(keyPath)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode %v %v", st.Mode(), err)
	}
	s, err := LoadSigner(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	reg, err := LoadRegistry(regPath)
	if err != nil {
		t.Fatal(err)
	}
	w := s.Sign(PrefixHandoff, []byte("x"))
	if _, _, err := Verify(reg, w, PrefixHandoff, RoleAgent, t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	// Rotation: add an overlapping key, then revoke the old one.
	kid2, err := Keygen(KeygenOptions{Dir: filepath.Join(dir, "keys"), Registry: regPath, Agent: "investigator", Role: RoleAgent,
		KID: "investigator-rotated", NotBefore: t0, NotAfter: t0.Add(60 * 24 * time.Hour), Rand: rand.Reader})
	if err != nil || kid2 != "investigator-rotated" {
		t.Fatal(err)
	}
	if _, err := Keygen(KeygenOptions{Dir: filepath.Join(dir, "keys"), Registry: regPath, Agent: "investigator", Role: RoleAgent,
		KID: "investigator-rotated", NotBefore: t0, NotAfter: t0.Add(time.Hour), Rand: rand.Reader}); !errors.Is(err, value.ErrConfig) {
		t.Fatal("duplicate key ID accepted")
	}
	if err := Revoke(regPath, kid); err != nil {
		t.Fatal(err)
	}
	reg, _ = LoadRegistry(regPath)
	if _, _, err := Verify(reg, w, PrefixHandoff, RoleAgent, t0.Add(time.Hour)); !errors.Is(err, value.ErrUnknownKey) {
		t.Fatal("revoked key still verifies")
	}
	if err := Revoke(regPath, "nope"); err == nil {
		t.Fatal("revoking an unknown key")
	}
	// The loader refuses a key file readable by group or others.
	if err := os.Chmod(keyPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSigner(keyPath); !errors.Is(err, value.ErrKeyPermissions) {
		t.Fatalf("0644 key loaded: %v", err)
	}
	os.Chmod(keyPath, 0o600)
	os.WriteFile(filepath.Join(dir, "bad.key"), []byte(`{"kid":"x"}`), 0o600)
	if _, err := LoadSigner(filepath.Join(dir, "bad.key")); !errors.Is(err, value.ErrConfig) {
		t.Fatal("malformed key file")
	}
	if _, err := LoadSigner(filepath.Join(dir, "missing.key")); !errors.Is(err, value.ErrConfig) {
		t.Fatal("missing key file")
	}
	if _, err := LoadRegistry(filepath.Join(dir, "missing.json")); !errors.Is(err, value.ErrConfig) {
		t.Fatal("missing registry")
	}
	if _, err := Keygen(KeygenOptions{Agent: "x", Role: "admin"}); !errors.Is(err, value.ErrConfig) {
		t.Fatal("bad keygen options")
	}
	os.WriteFile(filepath.Join(dir, "garbage.json"), []byte("{"), 0o644)
	if _, err := Keygen(KeygenOptions{Dir: dir, Registry: filepath.Join(dir, "garbage.json"), Agent: "x", Role: RoleAgent, NotBefore: t0, NotAfter: t0.Add(time.Hour), Rand: rand.Reader}); err == nil {
		t.Fatal("corrupt registry accepted")
	}
}

func TestFilesystemFailuresAreReported(t *testing.T) {
	dir := t.TempDir()
	ro := filepath.Join(dir, "ro")
	if err := os.Mkdir(ro, 0o500); err != nil {
		t.Fatal(err)
	}
	opts := KeygenOptions{Dir: filepath.Join(dir, "keys"), Registry: filepath.Join(ro, "registry.json"), Agent: "x", Role: RoleAgent,
		NotBefore: t0, NotAfter: t0.Add(time.Hour), Rand: rand.Reader}
	if _, err := Keygen(opts); err == nil {
		t.Fatal("registry in a read-only directory")
	}
	file := filepath.Join(dir, "afile")
	os.WriteFile(file, []byte("x"), 0o600)
	opts.Dir, opts.Registry = filepath.Join(file, "keys"), filepath.Join(dir, "r.json")
	if _, err := Keygen(opts); err == nil {
		t.Fatal("key directory under a file")
	}
	if err := Revoke(filepath.Join(dir, "none.json"), "k"); err == nil {
		t.Fatal("revoke without a registry")
	}
	keysDir := filepath.Join(dir, "k2")
	os.Mkdir(keysDir, 0o700)
	if _, err := LoadSigner(keysDir); err == nil {
		t.Fatal("a directory is not a key file")
	}
	if _, err := DecodeWire([]byte(`{"payload":"","kid":"k","sig":"s"}`), 100); !errors.Is(err, value.ErrSchema) {
		t.Fatal("empty payload")
	}
	if _, err := DecodeWire([]byte(`{`), 100); !errors.Is(err, value.ErrSchema) {
		t.Fatal("malformed wire")
	}
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	reg, _ := NewRegistry(NewKey("k", "a", RoleAgent, pub, t0, t0.Add(time.Hour), StatusActive))
	if k, _ := reg.Lookup("k", t0); !bytes.Equal(k.Pub(), pub) {
		t.Fatal("Pub")
	}
	if _, err := NewRegistry(Key{KID: "bad"}); !errors.Is(err, value.ErrConfig) {
		t.Fatal("NewRegistry validation")
	}
}
