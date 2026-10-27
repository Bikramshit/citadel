// Package plan defines the restricted plan language a planner writes, its
// strict JSON decoding, and StaticCheck, which rejects a whole plan before
// any statement runs. The language has no string operations, no index or
// counter variables, and names every action as a literal field.
package plan

import (
	"encoding/json"
	"fmt"

	"citadel/internal/authz"
	"citadel/internal/value"
)

// Limits on plan size.
const (
	MaxPlanBytes  = 32 << 10
	MaxStatements = 64
	MaxDepth      = 4
	MaxAskBytes   = 512
	MaxArgs       = 8
	MaxInputs     = 8
)

// Expr is one expression. Op selects which fields apply.
type Expr struct {
	Op     string          `json:"op"` // lit | ref | param | field | call | extract
	Lit    json.RawMessage `json:"lit,omitempty"`
	Ref    string          `json:"ref,omitempty"`
	Param  string          `json:"param,omitempty"` // analyst parameter, labeled TaskParam
	Of     *Expr           `json:"of,omitempty"`
	Field  string          `json:"field,omitempty"`
	Tool   string          `json:"tool,omitempty"`
	Action string          `json:"action,omitempty"` // literal enum, never an argument
	Args   map[string]Expr `json:"args,omitempty"`
	Inputs []Expr          `json:"inputs,omitempty"` // extract
	Schema string          `json:"schema,omitempty"` // extract: registered Go type
	Ask    string          `json:"ask,omitempty"`    // extract: planner-written instruction
}

// HandoffStmt asks another agent to perform a task with typed data.
type HandoffStmt struct {
	To           string          `json:"to"`
	Task         string          `json:"task"`
	RequestedOps []authz.Op      `json:"requested_ops,omitempty"`
	Data         map[string]Expr `json:"data"`
}

// Plan is a planner's output.
type Plan struct {
	Agent string `json:"agent"`
	Steps []Stmt `json:"steps"`
}

// Stmt is one statement.
type Stmt struct {
	Op      string       `json:"op"` // let | call | for_each | if | handoff
	Var     string       `json:"var,omitempty"`
	Expr    *Expr        `json:"expr,omitempty"`
	Over    *Expr        `json:"over,omitempty"` // for_each; no index variable is exposed
	Cond    *Cond        `json:"cond,omitempty"` // if; rejected at runtime when untrusted
	Body    []Stmt       `json:"body,omitempty"`
	Else    []Stmt       `json:"else,omitempty"`
	Handoff *HandoffStmt `json:"handoff,omitempty"`
}

// Cond is an if condition.
type Cond struct {
	Op    string `json:"op"` // eq | not_empty | in
	Left  Expr   `json:"left"`
	Right *Expr  `json:"right,omitempty"`
}

// Decode parses a plan strictly: size limit, unknown fields, duplicate keys,
// and wrong types (an action written as an expression, for example) are all
// rejected. Plans carry no labels; the runtime labels literals.
func Decode(b []byte) (Plan, error) {
	var p Plan
	if err := value.DecodeStrict(b, &p, value.Limits{MaxBytes: MaxPlanBytes, MaxDepth: 24}); err != nil {
		return Plan{}, fmt.Errorf("%w: plan: %w", value.ErrPlanInvalid, err)
	}
	return p, nil
}

// Encode renders a plan as JSON.
func Encode(p Plan) ([]byte, error) { return json.Marshal(p) }
