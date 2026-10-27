// Package llm defines the planner, processor, and intake interfaces, the
// registered processor schemas with strict decoding, the pure prompt
// builders, and the model-call machinery (retries, backoff, rate limiting,
// timeouts, accounting). The provider-specific client that talks to a Meta
// model endpoint is a recorded dependency on the model-access gate
// (docs/GATE.md); until it is written, runs use internal/llm/scripted and
// record that they did.
//
// Model outputs carry no labels: the schemas here have no label fields, and
// unknown fields fail decoding. The processor is called without any tool
// definitions.
package llm

import (
	"context"
	"encoding/json"
	"time"

	"citadel/internal/authz"
	"citadel/internal/plan"
)

// Implementation names recorded in every run's metadata.
const (
	ImplScripted = "scripted"
	ImplModel    = "model"
)

// Param is one analyst parameter as the planner sees it: trusted, typed, and
// validated by the orchestrator.
type Param struct {
	Name  string          `json:"name"`
	Type  string          `json:"type"`
	Value json.RawMessage `json:"value"`
}

// DataDecl names a data handle and its type. Planners see names and types,
// never values or list lengths.
type DataDecl struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// SchemaDecl describes a registered processor schema.
type SchemaDecl struct {
	Name   string     `json:"name"`
	Fields []DataDecl `json:"fields"`
}

// PlannerInput is everything a planner may see: the catalog task, the
// analyst's parameters and note, effective capabilities, and data names and
// types. It has no field that can hold a data value.
type PlannerInput struct {
	Agent       string       `json:"agent"`
	Task        string       `json:"task"`
	TaskVersion int          `json:"task_version"`
	Params      []Param      `json:"params"`
	Note        string       `json:"note"`
	Effective   []authz.Cap  `json:"effective"`
	Handoffs    []HandoffTo  `json:"handoffs"`
	Data        []DataDecl   `json:"data"`
	Schemas     []SchemaDecl `json:"schemas"`
	HandoffData []DataDecl   `json:"handoff_data"` // what a handoff may carry
}

// HandoffTo is a handoff the agent may make.
type HandoffTo struct {
	To   string `json:"to"`
	Task string `json:"task"`
}

// CallInfo records one model interaction for run metadata.
type CallInfo struct {
	Impl         string        `json:"impl"` // scripted | model
	Model        string        `json:"model,omitempty"`
	Provider     string        `json:"provider,omitempty"`
	Calls        int           `json:"calls"`   // API calls made, including retries
	Retries      int           `json:"retries"` // invalid-output retries
	PromptHash   string        `json:"prompt_hash,omitempty"`
	InputTokens  int           `json:"input_tokens"`
	OutputTokens int           `json:"output_tokens"`
	Latency      time.Duration `json:"latency_ns"`
}

// Planner writes a plan from trusted input only.
type Planner interface {
	Plan(ctx context.Context, in PlannerInput) (plan.Plan, CallInfo, error)
}

// ExtractRequest asks the processor to fill a registered schema from
// untrusted inputs, rendered as text.
type ExtractRequest struct {
	Agent  string   `json:"agent"`
	Schema string   `json:"schema"`
	Ask    string   `json:"ask"`
	Inputs []string `json:"inputs"`
}

// Processor turns untrusted text into a registered schema's JSON. It has no
// tools. Its output is always untrusted.
type Processor interface {
	Extract(ctx context.Context, req ExtractRequest) (json.RawMessage, CallInfo, error)
}

// IntakeRequest is the C1-instr comparison's intake: the Responder's runtime
// turns a peer's free-text report into task parameters, as a runtime would
// that accepts a peer's message as the analyst's request. This configuration
// models laundering on purpose.
type IntakeRequest struct {
	Report string     `json:"report"`
	Data   []DataDecl `json:"data"`
}

// Intake returns the parameters it read from the report, as IOCList JSON.
type Intake interface {
	Intake(ctx context.Context, req IntakeRequest) (json.RawMessage, CallInfo, error)
}

// Set bundles the model roles an agent uses, with the implementation name
// recorded in run metadata.
type Set struct {
	Impl      string
	Planner   Planner
	Processor Processor
	Intake    Intake
}

// ToolDef describes one tool offered to a baseline (C0) agent.
type ToolDef struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Args        []string `json:"args"`
}

// ToolCall is one tool call a baseline agent makes.
type ToolCall struct {
	Name string            `json:"name"`
	Args map[string]string `json:"args"`
}

// ToolTurn is a baseline agent's next step: tool calls, or a final answer.
type ToolTurn struct {
	Calls []ToolCall `json:"calls,omitempty"`
	Final string     `json:"final,omitempty"`
}

// ToolAgent is ordinary tool calling with no Citadel runtime: the C0
// baseline. The harness executes its calls against the same mock tools.
type ToolAgent interface {
	Next(ctx context.Context, system string, transcript []Message, tools []ToolDef) (ToolTurn, CallInfo, error)
}
