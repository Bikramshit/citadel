package plan

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"unicode/utf8"

	"citadel/internal/authz"
	"citadel/internal/catalog"
	"citadel/internal/label"
	"citadel/internal/value"
)

// Violation is one reason a plan was rejected, with the rule it breaks.
type Violation struct {
	Rule   string `json:"rule"` // A1, I1, I2, I3, H1, H2, H3, or "schema"
	Path   string `json:"path"` // statement path, e.g. "steps[1].body[0]"
	Reason string `json:"reason"`
}

// RejectError lists every violation found in a plan. It wraps
// ERR_PLAN_REJECTED.
type RejectError struct {
	Violations []Violation
}

// Error summarizes the violations.
func (e *RejectError) Error() string {
	parts := make([]string, len(e.Violations))
	for i, v := range e.Violations {
		parts[i] = v.Rule + " at " + v.Path + ": " + v.Reason
	}
	return string(value.ErrPlanRejected) + ": " + strings.Join(parts, "; ")
}

// Unwrap returns ERR_PLAN_REJECTED.
func (e *RejectError) Unwrap() error { return value.ErrPlanRejected }

// Rules returns the distinct rule IDs the plan broke, in order of first
// appearance.
func (e *RejectError) Rules() []string {
	var out []string
	for _, v := range e.Violations {
		if !slices.Contains(out, v.Rule) {
			out = append(out, v.Rule)
		}
	}
	return out
}

// DataBinding describes a data handle visible to the plan, such as a list
// imported from a handoff.
type DataBinding struct {
	Type      value.Type
	Untrusted bool // false only for analyst-labeled data (the C1-instr intake)
}

// Env is everything StaticCheck needs.
type Env struct {
	Agent         string
	Eff           []authz.Cap
	Task          *catalog.Task
	Ctx           *authz.AuthContext
	Data          map[string]DataBinding           // imported data handles
	Schemas       map[string]map[string]value.Type // registered processor schemas: name -> field -> type
	HandoffSchema map[string]value.Type            // data a handoff may carry
	Hosts         value.HostSet                    // for typing host literals
}

// trust is the static trust class of an expression.
type trust uint8

const (
	tTrusted   trust = iota // literal, runtime, or inventory: trusted, cannot name a target
	tParam                  // analyst parameter: trusted, may name a target
	tUntrusted              // data: untrusted, may name a target through evidence rules
)

type binding struct {
	typ value.Type
	tr  trust
}

type checker struct {
	env     Env
	taskOps []authz.Cap
	scopes  []map[string]binding
	count   int
	vs      []Violation
}

func (c *checker) fail(rule, path, format string, args ...any) {
	c.vs = append(c.vs, Violation{Rule: rule, Path: path, Reason: fmt.Sprintf(format, args...)})
}

func (c *checker) lookup(name string) (binding, bool) {
	for i := len(c.scopes) - 1; i >= 0; i-- {
		if b, ok := c.scopes[i][name]; ok {
			return b, true
		}
	}
	if d, ok := c.env.Data[name]; ok {
		tr := tUntrusted
		if !d.Untrusted {
			tr = tParam
		}
		return binding{typ: d.Type, tr: tr}, true
	}
	return binding{}, false
}

func validName(s string) bool {
	if len(s) == 0 || len(s) > 32 || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '_') {
			return false
		}
	}
	return true
}

func (c *checker) define(path, name string, b binding) {
	if !validName(name) {
		c.fail("schema", path, "invalid variable name %q", value.Truncate(name))
		return
	}
	if _, ok := c.lookup(name); ok {
		c.fail("schema", path, "variable %q is already defined", name)
		return
	}
	if c.env.Task != nil {
		if _, ok := c.env.Task.ParamType(name); ok {
			c.fail("schema", path, "variable %q shadows a parameter", name)
			return
		}
	}
	c.scopes[len(c.scopes)-1][name] = b
}

// StaticCheck runs before any statement executes. It rejects the whole plan
// if any call's (tool, action) is outside eff (A1) or the task's operations
// (I1), an action is not a literal from the tool's enum (I3), any target
// argument is a literal or a trusted non-parameter value (I2), a handoff is
// not in the workflow (H1), requests operations beyond the receiver's grant
// (H2), or runs under an untrusted loop (H3), a reference is undefined, or
// size limits are exceeded.
func StaticCheck(p Plan, env Env) error {
	c := &checker{env: env, scopes: []map[string]binding{{}}}
	if env.Task == nil || env.Ctx == nil {
		c.fail("schema", "plan", "no task or context to check against")
		return &RejectError{Violations: c.vs}
	}
	ops, err := env.Task.Ops(env.Agent, env.Ctx.Params)
	if err != nil {
		c.fail("I1", "plan", "catalog operations unavailable: %v", err)
	}
	c.taskOps = ops
	if p.Agent != env.Agent {
		c.fail("schema", "plan.agent", "plan is for %q, not %q", value.Truncate(p.Agent), env.Agent)
	}
	if len(p.Steps) == 0 {
		c.fail("schema", "plan.steps", "empty plan")
	}
	c.stmts(p.Steps, "steps", false, 1)
	if c.count > MaxStatements {
		c.fail("schema", "plan", "%d statements exceeds %d", c.count, MaxStatements)
	}
	if len(c.vs) > 0 {
		return &RejectError{Violations: c.vs}
	}
	return nil
}

func (c *checker) stmts(ss []Stmt, path string, untrustedPC bool, depth int) {
	if depth > MaxDepth {
		c.fail("schema", path, "nesting deeper than %d", MaxDepth)
		return
	}
	for i := range ss {
		c.stmt(&ss[i], fmt.Sprintf("%s[%d]", path, i), untrustedPC, depth)
	}
}

func (c *checker) withScope(f func()) {
	c.scopes = append(c.scopes, map[string]binding{})
	f()
	c.scopes = c.scopes[:len(c.scopes)-1]
}

func (c *checker) stmt(s *Stmt, path string, untrustedPC bool, depth int) {
	c.count++
	extra := func(fields ...bool) bool {
		for _, f := range fields {
			if f {
				c.fail("schema", path, "statement %q has fields it does not use", s.Op)
				return true
			}
		}
		return false
	}
	switch s.Op {
	case "let":
		if s.Expr == nil || extra(s.Over != nil, s.Cond != nil, s.Body != nil, s.Else != nil, s.Handoff != nil) {
			if s.Expr == nil {
				c.fail("schema", path, "let needs expr")
			}
			return
		}
		b, ok := c.expr(s.Expr, nil, path+".expr")
		if ok {
			c.define(path, s.Var, b)
		}
	case "call":
		if s.Expr == nil || s.Expr.Op != "call" || extra(s.Var != "", s.Over != nil, s.Cond != nil, s.Body != nil, s.Else != nil, s.Handoff != nil) {
			if s.Expr == nil || s.Expr.Op != "call" {
				c.fail("schema", path, "call statement needs a call expression")
			}
			return
		}
		c.expr(s.Expr, nil, path+".expr")
	case "for_each":
		if s.Over == nil || len(s.Body) == 0 || extra(s.Expr != nil, s.Cond != nil, s.Else != nil, s.Handoff != nil) {
			if s.Over == nil || len(s.Body) == 0 {
				c.fail("schema", path, "for_each needs over and a body")
			}
			return
		}
		over, ok := c.expr(s.Over, nil, path+".over")
		if !ok {
			return
		}
		if over.typ.Kind != value.KindList {
			c.fail("schema", path, "for_each over %s, not a list", over.typ)
			return
		}
		c.withScope(func() {
			c.define(path, s.Var, binding{typ: *over.typ.Elem, tr: over.tr})
			c.stmts(s.Body, path+".body", untrustedPC || over.tr == tUntrusted, depth+1)
		})
	case "if":
		if s.Cond == nil || len(s.Body) == 0 || extra(s.Var != "", s.Expr != nil, s.Over != nil, s.Handoff != nil) {
			if s.Cond == nil || len(s.Body) == 0 {
				c.fail("schema", path, "if needs cond and a body")
			}
			return
		}
		c.cond(s.Cond, path+".cond")
		c.withScope(func() { c.stmts(s.Body, path+".body", untrustedPC, depth+1) })
		if len(s.Else) > 0 {
			c.withScope(func() { c.stmts(s.Else, path+".else", untrustedPC, depth+1) })
		}
	case "handoff":
		if s.Handoff == nil || extra(s.Var != "", s.Expr != nil, s.Over != nil, s.Cond != nil, s.Body != nil, s.Else != nil) {
			if s.Handoff == nil {
				c.fail("schema", path, "handoff statement needs handoff")
			}
			return
		}
		c.handoff(s.Handoff, path+".handoff", untrustedPC)
	default:
		c.fail("schema", path, "unknown statement op %q", value.Truncate(s.Op))
	}
}

func (c *checker) cond(cd *Cond, path string) {
	left, ok := c.expr(&cd.Left, nil, path+".left")
	if !ok {
		return
	}
	switch cd.Op {
	case "eq":
		if cd.Right == nil {
			c.fail("schema", path, "eq needs right")
			return
		}
		if left.typ.Kind == value.KindList || left.typ.Kind == value.KindStruct || left.typ.Kind == value.KindRecord {
			c.fail("schema", path, "eq compares scalars, not %s", left.typ)
			return
		}
		if right, ok := c.expr(cd.Right, &left.typ, path+".right"); ok && !right.typ.Equal(left.typ) {
			c.fail("schema", path, "eq of %s and %s", left.typ, right.typ)
		}
	case "not_empty":
		if cd.Right != nil || left.typ.Kind != value.KindList {
			c.fail("schema", path, "not_empty takes one list")
		}
	case "in":
		if cd.Right == nil {
			c.fail("schema", path, "in needs right")
			return
		}
		lt := value.ListOf(left.typ)
		if right, ok := c.expr(cd.Right, &lt, path+".right"); ok && !right.typ.Equal(lt) {
			c.fail("schema", path, "in: %s is not %s", right.typ, lt)
		}
	default:
		c.fail("schema", path, "unknown condition op %q", value.Truncate(cd.Op))
	}
}

func (c *checker) handoff(h *HandoffStmt, path string, untrustedPC bool) {
	agent := c.env.Agent
	if !authz.Covers(c.env.Eff, authz.HandoffCap(h.To, h.Task)) || !c.env.Ctx.WorkflowAllows(agent, h.To, h.Task) {
		c.fail("H1", path, "no handoff capability or workflow entry for %s -> %s %s", agent, value.Truncate(h.To), value.Truncate(h.Task))
	}
	if untrustedPC {
		c.fail("H3", path, "handoff inside a loop over untrusted data")
	}
	if h.RequestedOps != nil {
		recv, err := c.env.Task.Ops(h.To, c.env.Ctx.Params)
		if err != nil || !authz.OpsSubsetOf(h.RequestedOps, authz.Intersect(c.env.Ctx.Grants[h.To], recv)) {
			c.fail("H2", path, "requested operations exceed the receiver's run grant ∩ task operations")
		}
	}
	if len(h.Data) == 0 {
		c.fail("schema", path, "handoff carries no data")
	}
	for _, name := range slices.Sorted(maps.Keys(h.Data)) {
		want, ok := c.env.HandoffSchema[name]
		if !ok {
			c.fail("schema", path, "data %q is not in the handoff schema", value.Truncate(name))
			continue
		}
		e := h.Data[name]
		if e.Op == "lit" {
			c.fail("H3", path+".data."+name, "instruction data must not be a literal")
			continue
		}
		if got, ok := c.expr(&e, &want, path+".data."+name); ok && !got.typ.Equal(want) {
			c.fail("schema", path+".data."+name, "data %q is %s, schema says %s", name, got.typ, want)
		}
	}
}

// expr type-checks an expression. expected types literals, which have no
// type of their own.
func (c *checker) expr(e *Expr, expected *value.Type, path string) (binding, bool) {
	shape := func(ok bool) bool {
		if !ok {
			c.fail("schema", path, "expression %q has fields it does not use", e.Op)
		}
		return ok
	}
	switch e.Op {
	case "lit":
		if !shape(e.Ref == "" && e.Param == "" && e.Of == nil && e.Field == "" && e.Tool == "" && e.Action == "" && e.Args == nil && e.Inputs == nil && e.Schema == "" && e.Ask == "") {
			return binding{}, false
		}
		if expected == nil {
			c.fail("schema", path, "literal in a position with no type")
			return binding{}, false
		}
		if _, err := value.FromJSON(e.Lit, *expected, c.env.Hosts, label.New(label.PlannerLiteral(c.env.Agent))); err != nil {
			c.fail("schema", path, "literal is not a valid %s: %v", *expected, err)
			return binding{}, false
		}
		return binding{typ: *expected, tr: tTrusted}, true
	case "ref":
		if !shape(e.Lit == nil && e.Param == "" && e.Of == nil && e.Field == "" && e.Tool == "" && e.Action == "" && e.Args == nil && e.Inputs == nil && e.Schema == "" && e.Ask == "") {
			return binding{}, false
		}
		b, ok := c.lookup(e.Ref)
		if !ok {
			c.fail("schema", path, "undefined reference %q", value.Truncate(e.Ref))
		}
		return b, ok
	case "param":
		if !shape(e.Lit == nil && e.Ref == "" && e.Of == nil && e.Field == "" && e.Tool == "" && e.Action == "" && e.Args == nil && e.Inputs == nil && e.Schema == "" && e.Ask == "") {
			return binding{}, false
		}
		t, ok := c.env.Task.ParamType(e.Param)
		if !ok {
			c.fail("schema", path, "unknown parameter %q", value.Truncate(e.Param))
		}
		return binding{typ: t, tr: tParam}, ok
	case "field":
		if !shape(e.Lit == nil && e.Ref == "" && e.Param == "" && e.Of != nil && e.Tool == "" && e.Action == "" && e.Args == nil && e.Inputs == nil && e.Schema == "" && e.Ask == "") {
			return binding{}, false
		}
		of, ok := c.expr(e.Of, nil, path+".of")
		if !ok {
			return binding{}, false
		}
		fields, isSchema := c.env.Schemas[of.typ.Name]
		if of.typ.Kind != value.KindStruct || !isSchema {
			c.fail("schema", path, "field of %s, not a registered schema", of.typ)
			return binding{}, false
		}
		ft, ok := fields[e.Field]
		if !ok {
			c.fail("schema", path, "schema %s has no field %q", of.typ.Name, value.Truncate(e.Field))
			return binding{}, false
		}
		return binding{typ: ft, tr: of.tr}, true
	case "call":
		if !shape(e.Lit == nil && e.Ref == "" && e.Param == "" && e.Of == nil && e.Field == "" && e.Inputs == nil && e.Schema == "" && e.Ask == "") {
			return binding{}, false
		}
		return c.call(e, path)
	case "extract":
		if !shape(e.Lit == nil && e.Ref == "" && e.Param == "" && e.Of == nil && e.Field == "" && e.Tool == "" && e.Action == "" && e.Args == nil) {
			return binding{}, false
		}
		if _, ok := c.env.Schemas[e.Schema]; !ok {
			c.fail("schema", path, "unregistered schema %q", value.Truncate(e.Schema))
			return binding{}, false
		}
		if len(e.Inputs) == 0 || len(e.Inputs) > MaxInputs {
			c.fail("schema", path, "extract needs 1 to %d inputs", MaxInputs)
			return binding{}, false
		}
		if len(e.Ask) > MaxAskBytes || !utf8.ValidString(e.Ask) {
			c.fail("schema", path, "ask longer than %d bytes or not UTF-8", MaxAskBytes)
			return binding{}, false
		}
		for i := range e.Inputs {
			if _, ok := c.expr(&e.Inputs[i], nil, fmt.Sprintf("%s.inputs[%d]", path, i)); !ok {
				return binding{}, false
			}
		}
		return binding{typ: value.StructType(e.Schema), tr: tUntrusted}, true
	}
	c.fail("schema", path, "unknown expression op %q", value.Truncate(e.Op))
	return binding{}, false
}

func (c *checker) call(e *Expr, path string) (binding, bool) {
	op := authz.Op{Tool: e.Tool, Action: e.Action}
	ok := true
	if !slices.Contains(authz.Actions(e.Tool), e.Action) {
		c.fail("I3", path, "action %q is not a literal from the enum of tool %q", value.Truncate(e.Action), value.Truncate(e.Tool))
		ok = false
	}
	spec, callable := authz.Spec(op)
	if !callable {
		c.fail("A1", path, "%s is not a callable tool operation", value.Truncate(op.String()))
		return binding{}, false
	}
	if !authz.CoversOp(c.env.Eff, op) {
		c.fail("A1", path, "%s is not in the agent's effective capabilities", op)
		ok = false
	}
	if !authz.CoversOp(c.taskOps, op) {
		c.fail("I1", path, "%s is not an operation of task %s for %s", op, c.env.Task.Name, c.env.Agent)
		ok = false
	}
	if len(e.Args) > MaxArgs {
		c.fail("schema", path, "too many arguments")
		return binding{}, false
	}
	for name := range e.Args {
		if _, known := spec.Arg(name); !known {
			c.fail("schema", path, "%s has no argument %q", op, value.Truncate(name))
			ok = false
		}
	}
	var invKey string
	for _, a := range spec.Args {
		ae, present := e.Args[a.Name]
		apath := path + ".args." + a.Name
		if !present {
			c.fail("schema", path, "%s needs argument %q", op, a.Name)
			ok = false
			continue
		}
		if a.Target && ae.Op == "lit" {
			c.fail("I2", apath, "a planner literal cannot name a target")
			ok = false
			continue
		}
		var got binding
		var good bool
		if ae.Op == "lit" {
			for _, t := range a.Types {
				if _, err := value.FromJSON(ae.Lit, t, c.env.Hosts, label.New(label.PlannerLiteral(c.env.Agent))); err == nil {
					got, good = c.expr(&ae, &t, apath)
					break
				}
			}
			if !good {
				c.fail("schema", apath, "literal is not a valid %s", a.Types[0])
				ok = false
				continue
			}
			if spec.OutputByKey != nil && a.Name == "key" {
				invKey = strings.Trim(string(ae.Lit), `"`)
			}
		} else {
			got, good = c.expr(&ae, nil, apath)
			if !good {
				ok = false
				continue
			}
		}
		if !a.Accepts(got.typ) {
			c.fail("schema", apath, "%s takes %s, got %s", a.Name, a.Types[0], got.typ)
			ok = false
		}
		if a.Target && got.tr == tTrusted {
			c.fail("I2", apath, "literals, notes, runtime, and inventory values cannot name targets")
			ok = false
		}
	}
	out := spec.Output
	if spec.OutputByKey != nil {
		t, known := spec.OutputByKey[invKey]
		if !known {
			c.fail("schema", path, "inventory.read key must be a literal from %v", slices.Sorted(maps.Keys(spec.OutputByKey)))
			return binding{}, false
		}
		out = t
	}
	tr := tTrusted
	if op == (authz.Op{Tool: "logs", Action: "read"}) {
		tr = tUntrusted
	}
	return binding{typ: out, tr: tr}, ok
}
