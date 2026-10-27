package llm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"citadel/internal/plan"
	"citadel/internal/value"
)

// Message is one chat message sent to a model.
type Message struct {
	Role    string `json:"role"` // system | user | assistant
	Content string `json:"content"`
}

// ModelRequest is a provider-neutral completion request. It never carries
// tool definitions: neither the planner nor the processor gets tools.
type ModelRequest struct {
	Model       string
	Messages    []Message
	JSONSchema  json.RawMessage // structured-output schema, when the provider supports one
	MaxTokens   int
	Temperature float64
}

// ModelResponse is a provider-neutral completion response.
type ModelResponse struct {
	Content      string
	InputTokens  int
	OutputTokens int
}

// ErrRateLimited and ErrServerError mark retryable model-call failures. A
// provider client wraps one of them for HTTP 429 and 5xx responses; any
// other error is final.
var (
	ErrRateLimited = errors.New("model rate limited")
	ErrServerError = errors.New("model server error")
)

// ModelClient sends one completion request to a configured endpoint. The
// implementation for the hackathon's Meta models is written once the gate
// supplies the provider's request format (docs/GATE.md).
type ModelClient interface {
	Complete(ctx context.Context, req ModelRequest) (ModelResponse, error)
	Provider() string
}

// Sleeper waits between retries; tests inject one that does not sleep.
type Sleeper func(ctx context.Context, d time.Duration) error

// RealSleep waits for d or until ctx is done.
func RealSleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// CallConfig configures model calls for one role.
type CallConfig struct {
	Model          string        // model ID from configuration; never hardcoded
	Timeout        time.Duration // per call
	MaxTokens      int
	Temperature    float64
	MaxBackoffs    int           // retries on rate-limit and server errors
	BaseBackoff    time.Duration // doubled per retry
	MinInterval    time.Duration // in-process rate limit between calls
	MaxPlanRetries int           // invalid planner output; the specification allows at most 2
}

// Validate checks the configuration.
func (c CallConfig) Validate() error {
	switch {
	case c.Model == "":
		return fmt.Errorf("%w: model ID missing", value.ErrConfig)
	case c.Timeout <= 0:
		return fmt.Errorf("%w: model call timeout must be positive", value.ErrConfig)
	case c.MaxPlanRetries < 0 || c.MaxPlanRetries > 2:
		return fmt.Errorf("%w: at most two retries for invalid plan JSON", value.ErrConfig)
	case c.MaxBackoffs < 0 || c.BaseBackoff < 0 || c.MinInterval < 0:
		return fmt.Errorf("%w: negative retry setting", value.ErrConfig)
	}
	return nil
}

// Usage is a running count of model calls and tokens, written to run
// metadata.
type Usage struct {
	mu           sync.Mutex
	Calls        int `json:"calls"`
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
	Backoffs     int `json:"backoffs"`
	PlanRetries  int `json:"plan_retries"`
}

func (u *Usage) add(calls, in, out, backoffs, planRetries int) {
	u.mu.Lock()
	u.Calls += calls
	u.InputTokens += in
	u.OutputTokens += out
	u.Backoffs += backoffs
	u.PlanRetries += planRetries
	u.mu.Unlock()
}

// Snapshot returns a copy of the counters.
func (u *Usage) Snapshot() Usage {
	u.mu.Lock()
	defer u.mu.Unlock()
	return Usage{Calls: u.Calls, InputTokens: u.InputTokens, OutputTokens: u.OutputTokens, Backoffs: u.Backoffs, PlanRetries: u.PlanRetries}
}

// Caller wraps a ModelClient with the specification's call discipline:
// per-call timeouts, an in-process rate limiter, backoff retries only on
// rate-limit and server errors, and a running usage count.
type Caller struct {
	client ModelClient
	cfg    CallConfig
	sleep  Sleeper
	log    *slog.Logger
	usage  *Usage

	mu   sync.Mutex
	last time.Time
	now  func() time.Time
}

// NewCaller validates cfg and returns a Caller.
func NewCaller(client ModelClient, cfg CallConfig, sleep Sleeper, now func() time.Time, log *slog.Logger, usage *Usage) (*Caller, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if client == nil || sleep == nil || now == nil || log == nil || usage == nil {
		return nil, fmt.Errorf("%w: model caller dependencies missing", value.ErrConfig)
	}
	return &Caller{client: client, cfg: cfg, sleep: sleep, log: log, usage: usage, now: now}, nil
}

func (c *Caller) waitTurn(ctx context.Context) error {
	c.mu.Lock()
	wait := c.last.Add(c.cfg.MinInterval).Sub(c.now())
	if wait < 0 {
		wait = 0
	}
	c.last = c.now().Add(wait)
	c.mu.Unlock()
	if wait > 0 {
		return c.sleep(ctx, wait)
	}
	return nil
}

// Complete sends one request, retrying with backoff only on rate-limit and
// server errors.
func (c *Caller) Complete(ctx context.Context, msgs []Message, schema json.RawMessage) (ModelResponse, CallInfo, error) {
	info := CallInfo{Impl: ImplModel, Model: c.cfg.Model, Provider: c.client.Provider()}
	start := c.now()
	backoff := c.cfg.BaseBackoff
	for attempt := 0; ; attempt++ {
		if err := c.waitTurn(ctx); err != nil {
			return ModelResponse{}, info, fmt.Errorf("%w: %w", value.ErrModel, err)
		}
		cctx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
		resp, err := c.client.Complete(cctx, ModelRequest{Model: c.cfg.Model, Messages: msgs, JSONSchema: schema, MaxTokens: c.cfg.MaxTokens, Temperature: c.cfg.Temperature})
		cancel()
		info.Calls++
		if err == nil {
			info.InputTokens += resp.InputTokens
			info.OutputTokens += resp.OutputTokens
			info.Latency = c.now().Sub(start)
			c.usage.add(1, resp.InputTokens, resp.OutputTokens, 0, 0)
			return resp, info, nil
		}
		c.usage.add(1, 0, 0, 0, 0)
		retryable := errors.Is(err, ErrRateLimited) || errors.Is(err, ErrServerError)
		if !retryable || attempt >= c.cfg.MaxBackoffs {
			info.Latency = c.now().Sub(start)
			return ModelResponse{}, info, fmt.Errorf("%w: %s after %d calls: %w", value.ErrModel, c.cfg.Model, info.Calls, err)
		}
		c.usage.add(0, 0, 0, 1, 0)
		c.log.Warn("model call retry", "model", c.cfg.Model, "attempt", attempt+1, "backoff", backoff.String(), "error", err.Error())
		if err := c.sleep(ctx, backoff); err != nil {
			return ModelResponse{}, info, fmt.Errorf("%w: %w", value.ErrModel, err)
		}
		backoff *= 2
	}
}

// ModelPlanner is a Planner backed by a model. Invalid planner output gets at
// most MaxPlanRetries further attempts, each logged; after that the run
// aborts and counts as a failure.
type ModelPlanner struct {
	Caller *Caller
	Log    *slog.Logger
}

// Plan asks the model for a plan and decodes it strictly.
func (m *ModelPlanner) Plan(ctx context.Context, in PlannerInput) (plan.Plan, CallInfo, error) {
	prompt := BuildPlannerPrompt(in)
	msgs := []Message{{Role: "system", Content: prompt.System}, {Role: "user", Content: prompt.User}}
	total := CallInfo{Impl: ImplModel, Model: m.Caller.cfg.Model, Provider: m.Caller.client.Provider(), PromptHash: prompt.Hash()}
	for attempt := 0; ; attempt++ {
		resp, info, err := m.Caller.Complete(ctx, msgs, nil)
		total.Calls += info.Calls
		total.InputTokens += info.InputTokens
		total.OutputTokens += info.OutputTokens
		total.Latency += info.Latency
		if err != nil {
			return plan.Plan{}, total, err
		}
		p, derr := plan.Decode([]byte(resp.Content))
		if derr == nil {
			return p, total, nil
		}
		if attempt >= m.Caller.cfg.MaxPlanRetries {
			return plan.Plan{}, total, fmt.Errorf("%w: after %d retries: %w", value.ErrPlanInvalid, attempt, derr)
		}
		total.Retries++
		m.Caller.usage.add(0, 0, 0, 0, 1)
		m.Log.Warn("invalid plan JSON; retrying", "agent", in.Agent, "retry", attempt+1, "error", value.Truncate(derr.Error()))
		msgs = append(msgs, Message{Role: "assistant", Content: value.Truncate(resp.Content)},
			Message{Role: "user", Content: "That output was not a valid plan: " + value.Truncate(derr.Error()) + ". Output only the JSON plan."})
	}
}

// ModelProcessor is a Processor backed by a model, called without tools.
type ModelProcessor struct {
	Caller *Caller
}

// Extract asks the model to fill a schema. The runtime decodes the result
// strictly; nothing here interprets it.
func (m *ModelProcessor) Extract(ctx context.Context, req ExtractRequest) (json.RawMessage, CallInfo, error) {
	prompt := BuildProcessorPrompt(req)
	resp, info, err := m.Caller.Complete(ctx, []Message{{Role: "system", Content: prompt.System}, {Role: "user", Content: prompt.User}}, nil)
	info.PromptHash = prompt.Hash()
	if err != nil {
		return nil, info, fmt.Errorf("%w: %w", value.ErrProcessor, err)
	}
	return json.RawMessage(resp.Content), info, nil
}

// ModelIntake is the C1-instr intake backed by the Responder's planner
// model.
type ModelIntake struct {
	Caller *Caller
}

// Intake turns a report into parameters.
func (m *ModelIntake) Intake(ctx context.Context, req IntakeRequest) (json.RawMessage, CallInfo, error) {
	prompt := BuildIntakePrompt(req)
	resp, info, err := m.Caller.Complete(ctx, []Message{{Role: "system", Content: prompt.System}, {Role: "user", Content: prompt.User}}, nil)
	info.PromptHash = prompt.Hash()
	if err != nil {
		return nil, info, fmt.Errorf("%w: %w", value.ErrProcessor, err)
	}
	return json.RawMessage(resp.Content), info, nil
}
