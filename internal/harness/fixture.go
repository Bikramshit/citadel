// Package harness runs Citadel's evaluation: fixtures, the four
// configurations (C0, C1-instr, C1-data, C2), goal predicates, the invariant
// checker, metrics with Wilson intervals, the table generator, run metadata,
// and threshold tuning. Security results come from environment diffs and
// policy events, never from what a model says it did.
package harness

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"citadel/internal/evidence"
	"citadel/internal/tools"
	"citadel/internal/value"
)

// Fixture kinds.
const (
	KindBenign = "benign"
	KindAttack = "attack"
	KindDev    = "dev"
)

// TaskSpec is the analyst's request in a fixture.
type TaskSpec struct {
	Principal string         `yaml:"principal"`
	Role      string         `yaml:"role"`
	Task      string         `yaml:"task"`
	Version   int            `yaml:"version"`
	Params    map[string]any `yaml:"params"`
	Note      string         `yaml:"note"`
}

// Change names one environment change, as tools.Change does.
type Change struct {
	Tool   string `yaml:"tool" json:"tool"`
	Action string `yaml:"action" json:"action"`
	Target string `yaml:"target" json:"target"`
}

func (c Change) key() string { return c.Tool + "." + c.Action + " " + c.Target }

// GroundTruth is what should happen in a fixture.
type GroundTruth struct {
	Required         []Change `yaml:"required"`          // changes the task needs
	Allowed          []Change `yaml:"allowed"`           // further changes that are acceptable
	Approve          []Change `yaml:"approve"`           // escalated calls the ground-truth approver approves
	KnownLimitations []Change `yaml:"known_limitations"` // expected, documented unauthorized effects (B12)
	ShouldNotBlock   []string `yaml:"should_not_block"`  // dev fixtures: addresses no threshold may corroborate
	Fabricated       []string `yaml:"fabricated"`        // dev fixtures: indicators that must always be denied
	UnlistedShared   []string `yaml:"unlisted_shared"`   // dev fixtures: the case no k fixes
}

// Predicate is an attack goal's condition over the environment diff.
type Predicate struct {
	AnyOf  []Change `yaml:"any_of"`  // the goal holds if any of these changes happened
	NoneOf []Change `yaml:"none_of"` // the goal holds if none of these happened (G4)
}

// Expected is a deterministic expectation for scripted runs of a fixture.
type Expected struct {
	Changes     []Change `yaml:"changes"`      // the exact diff under C2 with scripted models
	Escalations *int     `yaml:"escalations"`  // escalation count under C2
	DenyRules   []string `yaml:"deny_rules"`   // rules that must appear among denials
	AbortCode   string   `yaml:"abort_code"`   // the run's abort code, if it aborts
	Description string   `yaml:"description"`  // what the expectation shows
	Configs     []string `yaml:"only_configs"` // configurations the expectation applies to; default C2
}

// Generator builds records deterministically, so fixtures stay small.
type Generator struct {
	Kind          string `yaml:"kind"` // failed_logins | denied_logins | success_login | flows | requests
	IP            string `yaml:"ip"`
	Host          string `yaml:"host"`
	Count         int    `yaml:"count"`
	Start         string `yaml:"start"` // offset from now, e.g. "-40m"
	Step          string `yaml:"step"`  // spacing, e.g. "1m"
	State         string `yaml:"state"` // flows: established | syn_only
	Principal     string `yaml:"principal"`
	AttemptedUser string `yaml:"attempted_user"`
	UserAgent     string `yaml:"user_agent"`
	Path          string `yaml:"path"`
	XForwardedFor string `yaml:"x_forwarded_for"`
	Sensor        string `yaml:"sensor"`
	Pipeline      string `yaml:"pipeline"`
	Duplicate     bool   `yaml:"duplicate"` // deliver every record twice with the same event ID
	Status        int    `yaml:"status"`
}

// Fixture is one evaluation, development, or deterministic scenario.
type Fixture struct {
	ID          string                   `yaml:"id"`
	Kind        string                   `yaml:"kind"`
	Goal        string                   `yaml:"goal"`  // attack: G1, G2a, G2b, G3a, G3b, G4, G5
	Style       string                   `yaml:"style"` // attack: direct | downstream | mimicry
	Description string                   `yaml:"description"`
	Now         time.Time                `yaml:"now"`
	Task        TaskSpec                 `yaml:"task"`
	Inventory   tools.InventoryData      `yaml:"inventory"` // added to the base inventory
	Access      []evidence.AccessRecord  `yaml:"access"`
	Flows       []evidence.FlowRecord    `yaml:"flows"`
	Generate    []Generator              `yaml:"generate"`
	Blocked     []string                 `yaml:"blocked"`
	Faults      map[string][]tools.Fault `yaml:"faults"`
	GroundTruth GroundTruth              `yaml:"ground_truth"`
	Predicate   Predicate                `yaml:"goal_predicate"`
	Expected    *Expected                `yaml:"expected"`

	path string
}

// Path returns the file the fixture came from.
func (f *Fixture) Path() string { return f.path }

// LoadFixture reads and validates one fixture file.
func LoadFixture(path string) (*Fixture, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: fixture: %v", value.ErrConfig, err)
	}
	var f Fixture
	if err := value.DecodeYAMLStrict(b, &f); err != nil {
		return nil, fmt.Errorf("fixture %s: %w", path, err)
	}
	f.path = path
	if err := f.validate(); err != nil {
		return nil, fmt.Errorf("%w: fixture %s: %v", value.ErrConfig, path, err)
	}
	return &f, nil
}

// LoadFixtures reads every *.yaml under dir, sorted by ID.
func LoadFixtures(dir string) ([]*Fixture, error) {
	var paths []string
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(p, ".yaml") {
			paths = append(paths, p)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("%w: fixtures: %v", value.ErrConfig, err)
	}
	var out []*Fixture
	seen := map[string]bool{}
	for _, p := range paths {
		f, err := LoadFixture(p)
		if err != nil {
			return nil, err
		}
		if seen[f.ID] {
			return nil, fmt.Errorf("%w: fixture ID %s appears twice", value.ErrConfig, f.ID)
		}
		seen[f.ID] = true
		out = append(out, f)
	}
	slices.SortFunc(out, func(a, b *Fixture) int { return compareIDs(a.ID, b.ID) })
	return out, nil
}

// compareIDs orders IDs like B2 before B10.
func compareIDs(a, b string) int {
	pa, na := splitID(a)
	pb, nb := splitID(b)
	if pa != pb {
		return strings.Compare(pa, pb)
	}
	if na != nb {
		return na - nb
	}
	return strings.Compare(a, b)
}

func splitID(s string) (string, int) {
	i := len(s)
	for i > 0 && s[i-1] >= '0' && s[i-1] <= '9' {
		i--
	}
	j := i
	for j > 0 && (s[j-1] < '0' || s[j-1] > '9') && s[j-1] != '-' && s[j-1] != '_' {
		j--
	}
	n := 0
	for _, c := range s[i:] {
		n = n*10 + int(c-'0')
	}
	return s[:i], n
}

func (f *Fixture) validate() error {
	switch f.Kind {
	case KindBenign, KindAttack, KindDev:
	default:
		return fmt.Errorf("kind %q", f.Kind)
	}
	if f.ID == "" || f.Now.IsZero() || f.Task.Task == "" {
		return fmt.Errorf("id, now, and task are required")
	}
	if f.Kind == KindAttack && (f.Goal == "" || len(f.Predicate.AnyOf)+len(f.Predicate.NoneOf) == 0) {
		return fmt.Errorf("attack fixtures need a goal and a goal predicate")
	}
	for _, g := range f.Generate {
		if _, err := g.records(f.Now, 0); err != nil {
			return err
		}
	}
	return nil
}

func offset(now time.Time, s string, def time.Duration) (time.Time, error) {
	if s == "" {
		return now.Add(def), nil
	}
	neg := strings.HasPrefix(s, "-")
	d, err := value.ParseDuration(strings.TrimPrefix(s, "-"))
	if err != nil {
		return time.Time{}, err
	}
	if neg {
		d = -d
	}
	return now.Add(d), nil
}

type generated struct {
	access []evidence.AccessRecord
	flows  []evidence.FlowRecord
}

// records expands a generator.
func (g Generator) records(now time.Time, index int) (generated, error) {
	var out generated
	ip, err := value.ParseIPv4(g.IP)
	if err != nil {
		return out, fmt.Errorf("generator %s: %v", g.Kind, err)
	}
	start, err := offset(now, g.Start, -40*time.Minute)
	if err != nil {
		return out, fmt.Errorf("generator %s start: %v", g.Kind, err)
	}
	step := time.Minute
	if g.Step != "" {
		if step, err = value.ParseDuration(g.Step); err != nil {
			return out, fmt.Errorf("generator %s step: %v", g.Kind, err)
		}
	}
	n := max(g.Count, 1)
	sensor, pipe := g.Sensor, g.Pipeline
	host := g.Host
	if host == "" {
		host = "web-03"
	}
	prefix := fmt.Sprintf("g%d-%s-%s", index, g.Kind, strings.ReplaceAll(ip.String(), ".", "_"))
	switch g.Kind {
	case "failed_logins", "denied_logins", "success_login", "requests":
		if sensor == "" {
			sensor, pipe = "web-access", "web-logs"
		}
		for i := 0; i < n; i++ {
			r := evidence.AccessRecord{EventID: fmt.Sprintf("%s-%d", prefix, i), TS: start.Add(time.Duration(i) * step), Host: host,
				ClientIP: ip, SensorID: sensor, PipelineID: pipe, Path: g.Path, UserAgent: g.UserAgent,
				XForwardedFor: g.XForwardedFor, AttemptedUser: g.AttemptedUser}
			switch g.Kind {
			case "failed_logins":
				r.Status, r.AuthResult = 401, "fail"
				if r.Path == "" {
					r.Path = "/login"
				}
			case "denied_logins":
				r.Status = 403
				if r.Path == "" {
					r.Path = "/login"
				}
			case "success_login":
				r.Status, r.AuthResult, r.AuthPrincipal = 200, "success", g.Principal
				if r.Path == "" {
					r.Path = "/login"
				}
			case "requests":
				r.Status = 200
				if g.Status != 0 {
					r.Status = g.Status
				}
				if r.Path == "" {
					r.Path = "/"
				}
			}
			out.access = append(out.access, r)
			if g.Duplicate {
				out.access = append(out.access, r)
			}
		}
	case "flows":
		if sensor == "" {
			sensor, pipe = "net-flows", "netflow"
		}
		state := g.State
		if state == "" {
			state = evidence.FlowEstablished
		}
		for i := 0; i < n; i++ {
			out.flows = append(out.flows, evidence.FlowRecord{FlowID: fmt.Sprintf("%s-%d", prefix, i), TS: start.Add(time.Duration(i) * step),
				SrcIP: ip, DstHost: host, State: state, SensorID: sensor, PipelineID: pipe})
		}
	default:
		return out, fmt.Errorf("unknown generator kind %q", g.Kind)
	}
	return out, nil
}

// EnvSpec builds the fixture's environment on top of the base inventory.
func (f *Fixture) EnvSpec(base tools.InventoryData) (tools.Spec, error) {
	inv := base
	inv.Hosts = append(slices.Clone(base.Hosts), f.Inventory.Hosts...)
	inv.InternalRanges = append(slices.Clone(base.InternalRanges), f.Inventory.InternalRanges...)
	inv.ProtectedIPs = append(slices.Clone(base.ProtectedIPs), f.Inventory.ProtectedIPs...)
	inv.Accounts = append(slices.Clone(base.Accounts), f.Inventory.Accounts...)
	inv.ProtectedAccounts = append(slices.Clone(base.ProtectedAccounts), f.Inventory.ProtectedAccounts...)
	inv.PartnerIPs = append(slices.Clone(base.PartnerIPs), f.Inventory.PartnerIPs...)
	inv.SharedIPs = append(slices.Clone(base.SharedIPs), f.Inventory.SharedIPs...)
	inv.Sensors = append(slices.Clone(base.Sensors), f.Inventory.Sensors...)
	spec := tools.Spec{Inventory: inv, Access: slices.Clone(f.Access), Flows: slices.Clone(f.Flows), Blocked: f.Blocked, Faults: f.Faults}
	for i, g := range f.Generate {
		gen, err := g.records(f.Now, i)
		if err != nil {
			return tools.Spec{}, err
		}
		spec.Access = append(spec.Access, gen.access...)
		spec.Flows = append(spec.Flows, gen.flows...)
	}
	return spec, nil
}

// ParamsJSON renders the fixture's parameters for the orchestrator.
func (f *Fixture) ParamsJSON() (map[string]json.RawMessage, error) {
	out := map[string]json.RawMessage{}
	for k, v := range f.Task.Params {
		b, err := json.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("%w: fixture %s param %s: %v", value.ErrConfig, f.ID, k, err)
		}
		out[k] = b
	}
	return out, nil
}

// AttackerTexts returns every attacker-written string in the fixture's
// records, for the planner-input test.
func (f *Fixture) AttackerTexts(base tools.InventoryData) ([]string, error) {
	spec, err := f.EnvSpec(base)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, r := range spec.Access {
		for _, s := range []string{r.Path, r.UserAgent, r.XForwardedFor, r.AttemptedUser} {
			if s != "" && s != "/login" && s != "/" && !slices.Contains(out, s) {
				out = append(out, s)
			}
		}
	}
	return out, nil
}

// LoadBaseInventory reads configs/inventory.yaml.
func LoadBaseInventory(path string) (tools.InventoryData, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return tools.InventoryData{}, fmt.Errorf("%w: inventory: %v", value.ErrConfig, err)
	}
	var d tools.InventoryData
	if err := value.DecodeYAMLStrict(b, &d); err != nil {
		return tools.InventoryData{}, fmt.Errorf("inventory %s: %w", path, err)
	}
	return d, nil
}

// changeSet indexes changes.
func changeSet(cs ...[]Change) map[string]bool {
	m := map[string]bool{}
	for _, list := range cs {
		for _, c := range list {
			m[c.key()] = true
		}
	}
	return m
}

func fromToolChange(c tools.Change) Change {
	return Change{Tool: c.Tool, Action: c.Action, Target: c.Target}
}
