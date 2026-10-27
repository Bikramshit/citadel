package harness

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"citadel/internal/catalog"
	"citadel/internal/evidence"
	"citadel/internal/tools"
	"citadel/internal/value"
)

// TuningRule is the rule fixed in advance for choosing k.
const TuningRule = "smallest k at which no development address that should not be blocked is corroborated " +
	"(the unlisted shared-address case excepted, which no k fixes) and every fabricated indicator is denied"

// ThresholdsFile is configs/thresholds.yaml.
type ThresholdsFile struct {
	Rule            string          `yaml:"rule"`
	K               int             `yaml:"k"`
	MinFlows        int             `yaml:"min_flows"`
	SoftUntrustedPC int             `yaml:"soft_untrusted_pc"`
	IterationBudget int             `yaml:"iteration_budget"`
	Fixtures        []FixtureDigest `yaml:"fixtures"`
	Verified        []string        `yaml:"verified"`
	GeneratedAt     time.Time       `yaml:"generated_at"`
}

// FixtureDigest pins a fixture file's contents.
type FixtureDigest struct {
	ID     string `yaml:"id" json:"id"`
	SHA256 string `yaml:"sha256" json:"sha256"`
}

// Thresholds returns the tuned values.
func (f ThresholdsFile) Thresholds() Thresholds {
	return Thresholds{K: f.K, MinFlows: f.MinFlows, SoftUntrustedPC: f.SoftUntrustedPC, IterationBudget: f.IterationBudget}
}

// LoadThresholds reads and validates configs/thresholds.yaml.
func LoadThresholds(path string) (ThresholdsFile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return ThresholdsFile{}, fmt.Errorf("%w: thresholds: %v", value.ErrConfig, err)
	}
	var f ThresholdsFile
	if err := value.DecodeYAMLStrict(b, &f); err != nil {
		return ThresholdsFile{}, fmt.Errorf("thresholds %s: %w", path, err)
	}
	if f.K < 1 || f.MinFlows < 1 || f.SoftUntrustedPC < 1 || f.IterationBudget < 1 || f.Rule != TuningRule {
		return ThresholdsFile{}, fmt.Errorf("%w: thresholds %s: every value must be positive and the rule must be the fixed rule", value.ErrConfig, path)
	}
	return f, nil
}

func digest(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:]), nil
}

// TuneOptions configures Tune.
type TuneOptions struct {
	Catalog       *catalog.Catalog
	BaseInventory tools.InventoryData
	Defaults      Thresholds // the starting values for everything but k
	MaxK          int
	Rand          io.Reader
	Now           time.Time
}

// Tune chooses k by the fixed rule on development fixtures only, keeps the
// other thresholds at their starting values, and checks that every
// development task with required changes completes under them.
func Tune(ctx context.Context, fixtures []*Fixture, o TuneOptions) (ThresholdsFile, error) {
	if len(fixtures) == 0 {
		return ThresholdsFile{}, fmt.Errorf("%w: no development fixtures", value.ErrConfig)
	}
	out := ThresholdsFile{Rule: TuningRule, MinFlows: o.Defaults.MinFlows, SoftUntrustedPC: o.Defaults.SoftUntrustedPC,
		IterationBudget: o.Defaults.IterationBudget, GeneratedAt: o.Now.UTC()}
	type store struct {
		fx    *Fixture
		st    *evidence.Store
		scope evidence.TaskScope
	}
	var stores []store
	for _, fx := range fixtures {
		if fx.Kind != KindDev {
			return ThresholdsFile{}, fmt.Errorf("%w: tune reads development fixtures only; %s is %s", value.ErrConfig, fx.ID, fx.Kind)
		}
		d, err := digest(fx.Path())
		if err != nil {
			return ThresholdsFile{}, fmt.Errorf("tune: %w", err)
		}
		out.Fixtures = append(out.Fixtures, FixtureDigest{ID: fx.ID, SHA256: d})
		spec, err := fx.EnvSpec(o.BaseInventory)
		if err != nil {
			return ThresholdsFile{}, err
		}
		env, err := tools.NewEnv(spec, value.NewManualClock(fx.Now))
		if err != nil {
			return ThresholdsFile{}, err
		}
		window, err := value.ParseDuration(fmt.Sprint(fx.Task.Params["window"]))
		if err != nil {
			return ThresholdsFile{}, fmt.Errorf("%w: %s window", value.ErrConfig, fx.ID)
		}
		var hosts []string
		for _, h := range fx.Task.Params["hosts"].([]any) {
			hosts = append(hosts, fmt.Sprint(h))
		}
		stores = append(stores, store{fx: fx, st: env.Evidence(), scope: evidence.TaskScope{Hosts: hosts, From: fx.Now.Add(-window), To: fx.Now, LoginPath: "/login"}})
	}
	maxK := o.MaxK
	if maxK <= 0 {
		maxK = 50
	}
	chosen := 0
	for k := 1; k <= maxK && chosen == 0; k++ {
		th := evidence.Thresholds{K: k, MinFlows: o.Defaults.MinFlows}
		ok := true
		for _, s := range stores {
			for _, ip := range s.fx.GroundTruth.ShouldNotBlock {
				a, err := value.ParseIPv4(ip)
				if err != nil {
					return ThresholdsFile{}, fmt.Errorf("%w: %s should_not_block %q", value.ErrConfig, s.fx.ID, ip)
				}
				if v, _ := s.st.CorroborateIP(a, s.scope, th); v == evidence.EvCorroborated {
					ok = false
				}
			}
			for _, ip := range s.fx.GroundTruth.Fabricated {
				a, err := value.ParseIPv4(ip)
				if err != nil {
					return ThresholdsFile{}, fmt.Errorf("%w: %s fabricated %q", value.ErrConfig, s.fx.ID, ip)
				}
				if v, _ := s.st.CorroborateIP(a, s.scope, th); v != evidence.EvAbsent {
					ok = false
				}
			}
		}
		if ok {
			chosen = k
		}
	}
	if chosen == 0 {
		return ThresholdsFile{}, fmt.Errorf("%w: no k up to %d satisfies the tuning rule", value.ErrConfig, maxK)
	}
	out.K = chosen
	// The other thresholds keep their starting values; check that every
	// development task with required changes completes under them.
	for _, s := range stores {
		if len(s.fx.GroundTruth.Required) == 0 {
			continue
		}
		rec := Run(ctx, s.fx, Options{Config: C2, Catalog: o.Catalog, BaseInventory: o.BaseInventory, Thresholds: out.Thresholds(),
			Models: Scripted(nil), Rand: o.Rand})
		if rec.Crash != "" || !rec.Metrics.Completed || !rec.Valid() {
			return ThresholdsFile{}, fmt.Errorf("%w: development task %s does not complete under the thresholds: crash=%q diff=%v violations=%v",
				value.ErrConfig, s.fx.ID, rec.Crash, rec.Diff, rec.Violations)
		}
		out.Verified = append(out.Verified, s.fx.ID)
	}
	return out, nil
}

// WriteThresholds writes the tuned thresholds with an explanatory header.
func WriteThresholds(path string, f ThresholdsFile) error {
	var b strings.Builder
	b.WriteString("# Generated by `citadel tune` from development fixtures only (testdata/dev).\n")
	b.WriteString("# Commit this file before any evaluation run; `citadel harness` refuses to score\n")
	b.WriteString("# testdata/eval otherwise, and records this file's commit in every run.\n")
	fmt.Fprintf(&b, "rule: %q\n", f.Rule)
	fmt.Fprintf(&b, "k: %d\nmin_flows: %d\nsoft_untrusted_pc: %d\niteration_budget: %d\n", f.K, f.MinFlows, f.SoftUntrustedPC, f.IterationBudget)
	b.WriteString("fixtures:\n")
	for _, d := range f.Fixtures {
		fmt.Fprintf(&b, "  - {id: %s, sha256: %s}\n", d.ID, d.SHA256)
	}
	fmt.Fprintf(&b, "verified: [%s]\n", strings.Join(f.Verified, ", "))
	fmt.Fprintf(&b, "generated_at: %s\n", f.GeneratedAt.Format(time.RFC3339))
	return os.WriteFile(path, []byte(b.String()), 0o644)
}
