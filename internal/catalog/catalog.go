// Package catalog loads the fixed task catalog: task specifications decoded
// from YAML into fixed Go structs. It is not a policy language. The analyst
// sets a run's scope by picking a catalog task and filling in its typed
// parameters; the orchestrator validates them here, and the intent rule I1
// re-checks this catalog directly instead of trusting a context's grants.
package catalog

import (
	"encoding/json"
	"fmt"
	"maps"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"citadel/internal/authz"
	"citadel/internal/label"
	"citadel/internal/value"
)

// ParamSpec declares one typed analyst parameter.
type ParamSpec struct {
	Type      string `yaml:"type"`
	Min       int    `yaml:"min"`
	Max       string `yaml:"max"`        // list length, or a duration bound
	MustExist string `yaml:"must_exist"` // "inventory": hosts must exist
	Class     string `yaml:"class"`      // "public_external" for addresses
}

// ScopeSpec is a capability scope whose host and window may reference
// parameters as "$name".
type ScopeSpec struct {
	Hosts            string   `yaml:"hosts"`
	Window           string   `yaml:"window"`
	IPClass          string   `yaml:"ip_class"`
	AccountKinds     []string `yaml:"account_kinds"`
	ExcludeProtected bool     `yaml:"exclude_protected"`
}

// OpSpec is one operation a task grants an agent.
type OpSpec struct {
	Tool     string    `yaml:"tool"`
	Action   string    `yaml:"action"`
	When     string    `yaml:"when"` // "$bool_param": granted only when true
	Scope    ScopeSpec `yaml:"scope"`
	MaxCalls int       `yaml:"max_calls"`
}

// HandoffSpec permits a handoff to another agent.
type HandoffSpec struct {
	To   string `yaml:"to"`
	Task string `yaml:"task"`
	Max  int    `yaml:"max"`
}

// AgentSpec lists what a task grants one agent.
type AgentSpec struct {
	Ops      []OpSpec      `yaml:"ops"`
	Handoffs []HandoffSpec `yaml:"handoffs"`
}

// BudgetSpec holds a task's run budgets.
type BudgetSpec struct {
	MaxSensitiveCalls int    `yaml:"max_sensitive_calls"`
	TTL               string `yaml:"ttl"`
}

// Task is one catalog entry.
type Task struct {
	Name    string               `yaml:"task"`
	Version int                  `yaml:"version"`
	Roles   []string             `yaml:"roles"`
	Params  map[string]ParamSpec `yaml:"params"`
	Agents  map[string]AgentSpec `yaml:"agents"`
	Data    map[string]string    `yaml:"data"`
	Budgets BudgetSpec           `yaml:"budgets"`

	ttl        time.Duration
	paramTypes map[string]value.Type
	dataTypes  map[string]value.Type
}

// Catalog is the loaded, validated set of tasks.
type Catalog struct {
	Tasks []*Task `yaml:"tasks"`
}

// Load reads and validates a catalog file.
func Load(path string) (*Catalog, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: catalog: %v", value.ErrConfig, err)
	}
	return Parse(b)
}

// Parse decodes and validates catalog YAML.
func Parse(b []byte) (*Catalog, error) {
	var c Catalog
	if err := value.DecodeYAMLStrict(b, &c); err != nil {
		return nil, fmt.Errorf("catalog: %w", err)
	}
	if len(c.Tasks) == 0 {
		return nil, fmt.Errorf("%w: catalog has no tasks", value.ErrConfig)
	}
	seen := map[string]bool{}
	for _, t := range c.Tasks {
		if t == nil {
			return nil, fmt.Errorf("%w: empty catalog entry", value.ErrConfig)
		}
		if err := t.validate(); err != nil {
			return nil, fmt.Errorf("%w: task %q: %v", value.ErrConfig, t.Name, err)
		}
		k := t.Name + "@" + strconv.Itoa(t.Version)
		if seen[k] {
			return nil, fmt.Errorf("%w: task %s listed twice", value.ErrConfig, k)
		}
		seen[k] = true
	}
	return &c, nil
}

func (t *Task) validate() error {
	if t.Name == "" || t.Version < 1 || len(t.Roles) == 0 {
		return fmt.Errorf("name, version, and roles are required")
	}
	t.paramTypes = map[string]value.Type{}
	for name, p := range t.Params {
		ty, err := value.ParseType(p.Type)
		if err != nil {
			return fmt.Errorf("param %s: %v", name, err)
		}
		switch {
		case ty.Equal(value.ListOf(value.Scalar(value.KindHostname))), ty.Equal(value.ListOf(value.Scalar(value.KindIPv4))):
			if p.Max == "" {
				return fmt.Errorf("param %s: list needs max", name)
			}
			if n, err := strconv.Atoi(p.Max); err != nil || n < 1 || n < p.Min {
				return fmt.Errorf("param %s: bad max %q", name, p.Max)
			}
		case ty.Kind == value.KindDuration:
			if _, err := value.ParseDuration(p.Max); err != nil {
				return fmt.Errorf("param %s: bad max %q", name, p.Max)
			}
		case ty.Kind == value.KindBool:
		default:
			return fmt.Errorf("param %s: unsupported type %s", name, ty)
		}
		if p.MustExist != "" && p.MustExist != "inventory" {
			return fmt.Errorf("param %s: must_exist %q", name, p.MustExist)
		}
		if p.Class != "" && p.Class != authz.IPClassPublicExternal {
			return fmt.Errorf("param %s: class %q", name, p.Class)
		}
		t.paramTypes[name] = ty
	}
	t.dataTypes = map[string]value.Type{}
	for name, ts := range t.Data {
		ty, err := value.ParseType(ts)
		if err != nil || ty.Kind != value.KindList {
			return fmt.Errorf("data %s: type %q must be a list", name, ts)
		}
		t.dataTypes[name] = ty
	}
	if len(t.Agents) == 0 {
		return fmt.Errorf("no agents")
	}
	for agent, a := range t.Agents {
		for _, op := range a.Ops {
			if err := t.validateOp(op); err != nil {
				return fmt.Errorf("agent %s op %s.%s: %v", agent, op.Tool, op.Action, err)
			}
		}
		for _, h := range a.Handoffs {
			if _, ok := t.Agents[h.To]; !ok || h.Task == "" || h.Max < 1 || h.To == agent {
				return fmt.Errorf("agent %s: bad handoff %+v", agent, h)
			}
		}
	}
	if t.Budgets.MaxSensitiveCalls < 1 {
		return fmt.Errorf("budgets.max_sensitive_calls must be positive")
	}
	ttl, err := value.ParseDuration(t.Budgets.TTL)
	if err != nil {
		return fmt.Errorf("budgets.ttl: %v", err)
	}
	t.ttl = ttl
	return nil
}

func (t *Task) refType(ref string) (string, value.Type, error) {
	name, ok := strings.CutPrefix(ref, "$")
	if !ok {
		return "", value.Type{}, fmt.Errorf("%q is not a parameter reference", ref)
	}
	ty, ok := t.paramTypes[name]
	if !ok {
		return "", value.Type{}, fmt.Errorf("unknown parameter %q", ref)
	}
	return name, ty, nil
}

func (t *Task) validateOp(op OpSpec) error {
	if _, ok := authz.Spec(authz.Op{Tool: op.Tool, Action: op.Action}); !ok {
		return fmt.Errorf("unknown tool operation")
	}
	if op.MaxCalls < 0 {
		return fmt.Errorf("negative max_calls")
	}
	if op.When != "" {
		if _, ty, err := t.refType(op.When); err != nil || ty.Kind != value.KindBool {
			return fmt.Errorf("when must reference a bool parameter")
		}
	}
	if op.Scope.Hosts != "" {
		if _, ty, err := t.refType(op.Scope.Hosts); err != nil || !ty.Equal(value.ListOf(value.Scalar(value.KindHostname))) {
			return fmt.Errorf("scope.hosts must reference a list<hostname> parameter")
		}
	}
	if op.Scope.Window != "" {
		if _, ty, err := t.refType(op.Scope.Window); err != nil || ty.Kind != value.KindDuration {
			return fmt.Errorf("scope.window must reference a duration parameter")
		}
	}
	if op.Scope.IPClass != "" && op.Scope.IPClass != authz.IPClassPublicExternal {
		return fmt.Errorf("unknown ip_class %q", op.Scope.IPClass)
	}
	for _, k := range op.Scope.AccountKinds {
		if k != "user" && k != "service" {
			return fmt.Errorf("unknown account kind %q", k)
		}
	}
	if op.Scope.AccountKinds != nil && len(op.Scope.AccountKinds) == 0 {
		return fmt.Errorf("empty account_kinds")
	}
	return nil
}

// Lookup returns the task with this name and version.
func (c *Catalog) Lookup(name string, version int) (*Task, bool) {
	for _, t := range c.Tasks {
		if t.Name == name && t.Version == version {
			return t, true
		}
	}
	return nil, false
}

// Latest returns the highest version of the named task.
func (c *Catalog) Latest(name string) (*Task, bool) {
	var best *Task
	for _, t := range c.Tasks {
		if t.Name == name && (best == nil || t.Version > best.Version) {
			best = t
		}
	}
	return best, best != nil
}

// TTL returns the task's context lifetime.
func (t *Task) TTL() time.Duration { return t.ttl }

// ParamNames returns the task's parameter names, sorted.
func (t *Task) ParamNames() []string { return slices.Sorted(maps.Keys(t.Params)) }

// ParamType returns a parameter's type.
func (t *Task) ParamType(name string) (value.Type, bool) {
	ty, ok := t.paramTypes[name]
	return ty, ok
}

// DataNames returns the task's data names, sorted.
func (t *Task) DataNames() []string { return slices.Sorted(maps.Keys(t.Data)) }

// DataType returns a data item's type.
func (t *Task) DataType(name string) (value.Type, bool) {
	ty, ok := t.dataTypes[name]
	return ty, ok
}

// AgentNames returns the task's participating agents, sorted.
func (t *Task) AgentNames() []string { return slices.Sorted(maps.Keys(t.Agents)) }

// AllowsRole reports whether role may run the task.
func (t *Task) AllowsRole(role string) bool { return slices.Contains(t.Roles, role) }

// Inventory is what parameter validation needs from the system of record.
type Inventory interface {
	value.HostSet
	InternalRanges() []netip.Prefix
}

// ValidateParams checks the analyst's raw parameters deterministically
// (types, list bounds, hosts in the inventory, confirmed addresses public and
// external) and returns them in canonical JSON, with every parameter present:
// optional lists default to empty and booleans to false.
func (t *Task) ValidateParams(raw map[string]json.RawMessage, inv Inventory) (map[string]json.RawMessage, error) {
	for name := range raw {
		if _, ok := t.Params[name]; !ok {
			return nil, fmt.Errorf("%w: unknown parameter %q", value.ErrType, value.Truncate(name))
		}
	}
	out := make(map[string]json.RawMessage, len(t.Params))
	for _, name := range t.ParamNames() {
		p, ty := t.Params[name], t.paramTypes[name]
		r, present := raw[name]
		if !present {
			switch {
			case ty.Kind == value.KindBool:
				out[name] = json.RawMessage("false")
				continue
			case ty.Kind == value.KindList && p.Min == 0:
				out[name] = json.RawMessage("[]")
				continue
			}
			return nil, fmt.Errorf("%w: parameter %q is required", value.ErrType, name)
		}
		v, err := value.FromJSON(r, ty, inv, label.New(label.TaskParam(name)))
		if err != nil {
			return nil, fmt.Errorf("parameter %q: %w", name, err)
		}
		if err := checkParam(name, p, ty, v, inv); err != nil {
			return nil, err
		}
		out[name] = v.ToJSON()
	}
	return out, nil
}

func checkParam(name string, p ParamSpec, ty value.Type, v value.Value, inv Inventory) error {
	switch ty.Kind {
	case value.KindList:
		n, _ := strconv.Atoi(p.Max) // validated at load
		if v.Count() < p.Min || v.Count() > n {
			return fmt.Errorf("%w: parameter %q needs %d to %d items", value.ErrType, name, p.Min, n)
		}
		seen := map[string]bool{}
		for _, e := range v.Elems() {
			c := e.Canonical()
			if seen[c] {
				return fmt.Errorf("%w: parameter %q repeats %q", value.ErrType, name, c)
			}
			seen[c] = true
			if a, ok := e.AsIPv4(); ok && p.Class == authz.IPClassPublicExternal && !authz.PublicExternal(a, inv.InternalRanges()) {
				return fmt.Errorf("%w: parameter %q: %s is not public and external", value.ErrType, name, c)
			}
		}
	case value.KindDuration:
		bound, _ := value.ParseDuration(p.Max) // validated at load
		if d, _ := v.AsDuration(); d > bound {
			return fmt.Errorf("%w: parameter %q exceeds %s", value.ErrType, name, p.Max)
		}
	}
	return nil
}

// ParamValues decodes a context's validated parameters into labeled values,
// each labeled TaskParam(name).
func (t *Task) ParamValues(params map[string]json.RawMessage, hosts value.HostSet) (map[string]value.Value, error) {
	out := make(map[string]value.Value, len(t.paramTypes))
	for _, name := range t.ParamNames() {
		r, ok := params[name]
		if !ok {
			return nil, fmt.Errorf("%w: context lacks parameter %q", value.ErrAuthCtx, name)
		}
		v, err := value.FromJSON(r, t.paramTypes[name], hosts, label.New(label.TaskParam(name)))
		if err != nil {
			return nil, fmt.Errorf("parameter %q: %w", name, err)
		}
		out[name] = v
	}
	for name := range params {
		if _, ok := t.paramTypes[name]; !ok {
			return nil, fmt.Errorf("%w: context has unknown parameter %q", value.ErrAuthCtx, name)
		}
	}
	return out, nil
}

// Ops evaluates the task's operations for agent with the run's validated
// parameters: parameter references are substituted and operations whose
// "when" parameter is false are left out. Handoff permissions appear as
// handoff.request capabilities.
func (t *Task) Ops(agent string, params map[string]json.RawMessage) ([]authz.Cap, error) {
	a, ok := t.Agents[agent]
	if !ok {
		return []authz.Cap{}, nil
	}
	vals, err := t.ParamValues(params, nil)
	if err != nil {
		return nil, err
	}
	out := []authz.Cap{}
	for _, op := range a.Ops {
		if op.When != "" {
			if b, _ := vals[strings.TrimPrefix(op.When, "$")].AsBool(); !b {
				continue
			}
		}
		s := authz.Scope{
			IPClass:          op.Scope.IPClass,
			ExcludeProtected: op.Scope.ExcludeProtected,
			MaxCalls:         op.MaxCalls,
		}
		if op.Scope.AccountKinds != nil {
			s.AccountKinds = slices.Sorted(slices.Values(op.Scope.AccountKinds))
		}
		if op.Scope.Hosts != "" {
			hv := vals[strings.TrimPrefix(op.Scope.Hosts, "$")]
			s.Hosts = []string{}
			for _, e := range hv.Elems() {
				h, _ := e.AsString()
				s.Hosts = append(s.Hosts, h)
			}
			slices.Sort(s.Hosts)
		}
		if op.Scope.Window != "" {
			s.Window, _ = vals[strings.TrimPrefix(op.Scope.Window, "$")].AsDuration()
		}
		out = append(out, authz.Cap{Tool: op.Tool, Action: op.Action, Scope: s})
	}
	for _, h := range a.Handoffs {
		out = append(out, authz.HandoffCap(h.To, h.Task))
	}
	return out, nil
}

// Workflow returns the task's handoff grants for every agent, sorted.
func (t *Task) Workflow() []authz.HandoffGrant {
	var out []authz.HandoffGrant
	for _, agent := range t.AgentNames() {
		for _, h := range t.Agents[agent].Handoffs {
			out = append(out, authz.HandoffGrant{From: agent, To: h.To, Task: h.Task, Max: h.Max})
		}
	}
	return out
}

// TaskOps adapts the catalog to authz.TaskOps for the receiver's own check.
func (c *Catalog) TaskOps(task string, version int, agent string, params map[string]json.RawMessage) ([]authz.Cap, bool, error) {
	t, ok := c.Lookup(task, version)
	if !ok {
		return nil, false, nil
	}
	ops, err := t.Ops(agent, params)
	if err != nil {
		return nil, true, err
	}
	return ops, true, nil
}
