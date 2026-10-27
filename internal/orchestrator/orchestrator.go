// Package orchestrator is the model-free source of authority. It validates
// an analyst's structured task request deterministically and mints a signed
// authorization context for the run. No model runs here, and no model ever
// translates the analyst's words into permissions.
package orchestrator

import (
	"encoding/json"
	"fmt"
	"io"
	"unicode/utf8"

	"citadel/internal/authz"
	"citadel/internal/catalog"
	"citadel/internal/signed"
	"citadel/internal/value"
)

// MaxNoteBytes bounds the analyst's free-text note.
const MaxNoteBytes = 1024

// TaskRequest is the analyst's structured task choice.
type TaskRequest struct {
	Principal string                     `json:"principal"`
	Role      string                     `json:"role"`
	Task      string                     `json:"task"`
	Version   int                        `json:"version"`
	Params    map[string]json.RawMessage `json:"params"`
	Note      string                     `json:"note"`
}

// Config configures an Orchestrator.
type Config struct {
	Catalog         *catalog.Catalog
	Inventory       catalog.Inventory
	Signer          *signed.Signer
	Clock           value.Clock
	Rand            io.Reader // crypto/rand.Reader outside tests
	PolicyVersion   string
	SoftUntrustedPC int // F3's soft budget, from thresholds.yaml
}

// Orchestrator mints authorization contexts.
type Orchestrator struct {
	cfg Config
}

// New validates cfg.
func New(cfg Config) (*Orchestrator, error) {
	if cfg.Catalog == nil || cfg.Inventory == nil || cfg.Signer == nil || cfg.Clock == nil || cfg.Rand == nil ||
		cfg.PolicyVersion == "" || cfg.SoftUntrustedPC < 1 {
		return nil, fmt.Errorf("%w: orchestrator configuration incomplete", value.ErrConfig)
	}
	return &Orchestrator{cfg: cfg}, nil
}

// NewRunID returns "run_" and 128 random bits, base64url. Run IDs are never
// reissued, even across orchestrator restarts.
func NewRunID(r io.Reader) (string, error) {
	var b [16]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return "", fmt.Errorf("orchestrator: random run id: %w", err)
	}
	return "run_" + signed.EncodeBase64(b[:]), nil
}

// Minted is a signed context and the context it encodes.
type Minted struct {
	Wire    signed.Wire
	Context *authz.AuthContext
	Payload []byte
}

// Mint validates req and returns a signed authorization context: the
// principal, a fresh run ID, the task and version, the validated
// parameters, the participating agents, each agent's granted operations
// with resource scopes, the permitted handoffs, the policy version, issue and
// expiry times, and budgets.
func (o *Orchestrator) Mint(req TaskRequest) (Minted, error) {
	task, ok := o.cfg.Catalog.Lookup(req.Task, req.Version)
	if !ok {
		return Minted{}, fmt.Errorf("%w: %s v%d is not in the catalog", value.ErrUnknownTask, value.Truncate(req.Task), req.Version)
	}
	if req.Principal == "" || len(req.Principal) > 64 {
		return Minted{}, fmt.Errorf("%w: principal missing", value.ErrConfig)
	}
	if !task.AllowsRole(req.Role) {
		return Minted{}, fmt.Errorf("%w: role %q may not run %s", value.ErrNotPrincipal, value.Truncate(req.Role), task.Name)
	}
	if len(req.Note) > MaxNoteBytes || !utf8.ValidString(req.Note) {
		return Minted{}, fmt.Errorf("%w: note longer than %d bytes or not UTF-8", value.ErrType, MaxNoteBytes)
	}
	params, err := task.ValidateParams(req.Params, o.cfg.Inventory)
	if err != nil {
		return Minted{}, err
	}
	runID, err := NewRunID(o.cfg.Rand)
	if err != nil {
		return Minted{}, err
	}
	now := o.cfg.Clock.Now()
	ac := &authz.AuthContext{
		V: authz.ContextVersion, RunID: runID, Principal: req.Principal, Role: req.Role,
		Task: task.Name, TaskVersion: task.Version, Params: params, UserNote: req.Note,
		Agents: task.AgentNames(), Grants: map[string][]authz.Cap{}, Workflow: task.Workflow(),
		PolicyVersion: o.cfg.PolicyVersion, IssuedAt: now, ExpiresAt: now.Add(task.TTL()),
		Budgets: authz.Budgets{MaxSensitiveCalls: task.Budgets.MaxSensitiveCalls, SoftUntrustedPC: o.cfg.SoftUntrustedPC},
	}
	for _, agent := range ac.Agents {
		ops, err := task.Ops(agent, params)
		if err != nil {
			return Minted{}, err
		}
		ac.Grants[agent] = ops
	}
	if err := ac.Validate(); err != nil {
		return Minted{}, err
	}
	return o.Sign(ac)
}

// Sign signs an authorization context behind the authctx prefix.
func (o *Orchestrator) Sign(ac *authz.AuthContext) (Minted, error) {
	p, err := json.Marshal(ac)
	if err != nil {
		return Minted{}, fmt.Errorf("orchestrator: encode context: %w", err)
	}
	return Minted{Wire: o.cfg.Signer.Sign(signed.PrefixAuthCtx, p), Context: ac, Payload: p}, nil
}
