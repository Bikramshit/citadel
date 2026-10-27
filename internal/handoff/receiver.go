package handoff

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"time"

	"citadel/internal/authz"
	"citadel/internal/catalog"
	"citadel/internal/events"
	"citadel/internal/label"
	"citadel/internal/runstate"
	"citadel/internal/signed"
	"citadel/internal/value"
)

// ReceiverConfig configures a Receiver.
type ReceiverConfig struct {
	Self           string
	Static         []authz.Cap
	Registry       *signed.Registry
	Runs           *runstate.Runs
	Replay         *runstate.ReplayTable
	Catalog        *catalog.Catalog
	Hosts          value.HostSet
	PolicyVersions []string
	Mode           string // C2, C1-instr, or C1-data
	Events         events.Sink
	Clock          value.Clock
}

// Receiver verifies incoming envelopes.
type Receiver struct {
	cfg ReceiverConfig
}

// NewReceiver validates cfg.
func NewReceiver(cfg ReceiverConfig) (*Receiver, error) {
	if cfg.Self == "" || cfg.Registry == nil || cfg.Runs == nil || cfg.Replay == nil || cfg.Catalog == nil ||
		len(cfg.PolicyVersions) == 0 || cfg.Events == nil || cfg.Clock == nil {
		return nil, fmt.Errorf("%w: receiver configuration incomplete", value.ErrConfig)
	}
	switch cfg.Mode {
	case ModeC2, ModeC1Instr, ModeC1Data:
	default:
		return nil, fmt.Errorf("%w: handoff mode %q", value.ErrConfig, cfg.Mode)
	}
	return &Receiver{cfg: cfg}, nil
}

// Staged holds a verified envelope's values, labeled and ready to install.
// Nothing in it has entered a run until CommitHandoff installs it.
type Staged struct {
	Run     *runstate.RunState
	Ctx     *authz.AuthContext
	CtxHash [32]byte
	CtxWire signed.Wire
	Task    *catalog.Task
	Eff     []authz.Cap
	Values  map[string]value.Value
	Payload Payload
	Bytes   int
}

// VerifyAuthCtx checks an embedded authorization context: an orchestrator
// key's signature over the authctx prefix and the exact bytes, strict
// decoding, structure, expiry, and a supported policy version. It returns
// the context and the SHA-256 of its signed payload bytes.
func VerifyAuthCtx(reg *signed.Registry, w signed.Wire, policyVersions []string, now time.Time) (*authz.AuthContext, [32]byte, error) {
	p, _, err := signed.Verify(reg, w, signed.PrefixAuthCtx, signed.RoleOrchestrator, now)
	if err != nil {
		return nil, [32]byte{}, fmt.Errorf("%w: %w", value.ErrAuthCtx, err)
	}
	var ac authz.AuthContext
	if err := value.DecodeStrict(p, &ac, value.Limits{MaxBytes: 32 << 10}); err != nil {
		return nil, [32]byte{}, fmt.Errorf("%w: %w", value.ErrAuthCtx, err)
	}
	if err := ac.Validate(); err != nil {
		return nil, [32]byte{}, err
	}
	if !now.Before(ac.ExpiresAt) {
		return nil, [32]byte{}, fmt.Errorf("%w: context expired", value.ErrAuthCtx)
	}
	if !slices.Contains(policyVersions, ac.PolicyVersion) {
		return nil, [32]byte{}, fmt.Errorf("%w: unsupported policy version %q", value.ErrAuthCtx, value.Truncate(ac.PolicyVersion))
	}
	return &ac, sha256.Sum256(p), nil
}

func checkFresh(p *Payload, now, startedAt time.Time) error {
	switch {
	case !now.Before(p.ExpiresAt):
		return fmt.Errorf("%w: envelope expired at %s", value.ErrExpired, p.ExpiresAt.Format(time.RFC3339))
	case !p.ExpiresAt.After(p.IssuedAt) || p.ExpiresAt.Sub(p.IssuedAt) > MaxLifetime:
		return fmt.Errorf("%w: lifetime %s exceeds %s", value.ErrTTL, p.ExpiresAt.Sub(p.IssuedAt), MaxLifetime)
	case p.IssuedAt.After(now.Add(MaxFuture)):
		return fmt.Errorf("%w: issued more than %s in the future", value.ErrTTL, MaxFuture)
	case p.IssuedAt.Before(startedAt):
		return fmt.Errorf("%w: issued before this receiver started", value.ErrPreStart)
	}
	return nil
}

// Verify runs receiver steps 1 to 11 in order, up to staging. Any failure
// rejects the whole envelope and imports nothing. Every failure after the
// replay table's Begin also finishes the replay entry as rejected with its
// code, so a retransmission gets the same answer; on success the entry stays
// processing until Accept commits. The signature is checked before the
// payload is parsed, so unauthenticated bytes reach only the outer decoder.
func (r *Receiver) Verify(body []byte, now time.Time) (st *Staged, err error) {
	// Step 1: size limit; strict decode of the outer object.
	w, err := signed.DecodeWire(body, MaxBody)
	if err != nil {
		return nil, err // ERR_SIZE or ERR_SCHEMA
	}
	// Steps 2 and 3: kid in the registry, active, inside its validity
	// window; signature over the prefix and the exact payload bytes.
	p, key, err := signed.Verify(r.cfg.Registry, w, signed.PrefixHandoff, "", now)
	if err != nil {
		return nil, err // ERR_UNKNOWN_KEY, ERR_SCHEMA, or ERR_BAD_SIG
	}
	// Step 4: strict decode of P; P.kid equals the outer kid.
	var P Payload
	if err := value.DecodeStrict(p, &P, value.Limits{MaxBytes: MaxBody, MaxDepth: 8}); err != nil {
		return nil, err
	}
	if P.KID != w.KID || P.V != Version || !validID(P.ID) || P.RunID == "" || P.Task == "" {
		return nil, fmt.Errorf("%w: payload header", value.ErrSchema)
	}
	if err := checkStrings(&P); err != nil {
		return nil, err
	}
	// Step 5: the registry owner of kid is P.from; P.to is this agent.
	if key.Agent != P.From || key.Role != signed.RoleAgent {
		return nil, fmt.Errorf("%w: key %s belongs to %s, envelope claims %s", value.ErrSender, key.KID, key.Agent, value.Truncate(P.From))
	}
	if P.To != r.cfg.Self {
		return nil, fmt.Errorf("%w: envelope is for %s", value.ErrRecipient, value.Truncate(P.To))
	}
	// Step 6: freshness and the start-time watermark.
	if err := checkFresh(&P, now, r.cfg.Runs.StartedAt()); err != nil {
		return nil, err
	}
	// Step 7: the replay table.
	prior, err := r.cfg.Replay.Begin(P.From, P.ID, payloadDigest(p), P.ExpiresAt.Add(Skew), now)
	if err != nil {
		return nil, err // ERR_REPLAY or ERR_IN_PROGRESS
	}
	if prior != nil {
		return nil, prior.Result() // identical retransmission: recorded result, nothing imported
	}
	defer func() {
		if err != nil {
			code := value.CodeOf(err)
			if code == "" {
				code = string(value.ErrSchema)
			}
			r.cfg.Replay.Finish(P.From, P.ID, code)
		}
	}()
	// Step 8: the authorization context, bound to local run state.
	ac, acHash, err := VerifyAuthCtx(r.cfg.Registry, P.AuthCtx, r.cfg.PolicyVersions, now)
	if err != nil {
		return nil, err
	}
	if ac.RunID != P.RunID {
		return nil, fmt.Errorf("%w: context run %s differs from envelope run %s", value.ErrAuthCtx, ac.RunID, value.Truncate(P.RunID))
	}
	rs, err := r.cfg.Runs.Activate(ac, acHash, now)
	if err != nil {
		return nil, err // ERR_PRE_START, ERR_EXPIRED, ERR_NOT_PARTICIPANT, ERR_CONTEXT_CONFLICT, ERR_RUN_CLOSED
	}
	// Step 9: the workflow allows (from, to, task); task and version are in
	// this receiver's own catalog; requested_ops are within grant ∩ task.
	eff, err := authz.ReceiverEffective(r.cfg.Self, r.cfg.Static, ac, P.From, P.Task, P.TaskVersion, P.RequestedOps, r.cfg.Catalog.TaskOps)
	if err != nil {
		return nil, err // ERR_WORKFLOW, ERR_UNKNOWN_TASK, ERR_EXCESS_GRANT
	}
	task, _ := r.cfg.Catalog.Lookup(P.Task, P.TaskVersion) // ReceiverEffective found it
	// Step 10: every data item is in the task's schema with the right type
	// and limits. Step 11 (staging): build every handle, labeled Peer(from,
	// id) plus the claimed sources.
	vals, err := r.typedImport(&P, ac, task)
	if err != nil {
		return nil, err
	}
	return &Staged{Run: rs, Ctx: ac, CtxHash: acHash, CtxWire: P.AuthCtx, Task: task, Eff: eff, Values: vals, Payload: P, Bytes: len(body)}, nil
}

// typedImport parses every data item strictly into a labeled value. One bad
// item rejects the envelope: nothing is partial.
func (r *Receiver) typedImport(p *Payload, ac *authz.AuthContext, task *catalog.Task) (map[string]value.Value, error) {
	schema := DataSchema(task, r.cfg.Mode)
	claims := knownClaims(ac, task)
	out := map[string]value.Value{}
	for _, d := range p.Data {
		want, ok := schema[d.Name]
		if !ok {
			return nil, fmt.Errorf("%w: data %q is not in the schema", value.ErrType, value.Truncate(d.Name))
		}
		if _, dup := out[d.Name]; dup {
			return nil, fmt.Errorf("%w: data %q appears twice", value.ErrType, d.Name)
		}
		if d.Type != want.String() {
			return nil, fmt.Errorf("%w: data %q is %s, schema says %s", value.ErrType, d.Name, value.Truncate(d.Type), want)
		}
		srcs := []label.Source{label.Peer(p.From, p.ID)}
		for _, c := range d.ClaimedSources {
			if !claims[c] {
				return nil, fmt.Errorf("%w: claimed source %q is not on the fixed list", value.ErrType, value.Truncate(c))
			}
			srcs = append(srcs, label.Claimed(c))
		}
		l := label.New(srcs...)
		var v value.Value
		var err error
		if want.Kind == value.KindText {
			if len(d.Values) != 1 {
				return nil, fmt.Errorf("%w: data %q needs exactly one text value", value.ErrType, d.Name)
			}
			v, err = value.Text(d.Values[0], l)
		} else {
			if len(d.Values) > MaxValues {
				return nil, fmt.Errorf("%w: data %q has %d values, limit %d", value.ErrType, d.Name, len(d.Values), MaxValues)
			}
			elems := make([]value.Value, 0, len(d.Values))
			for _, s := range d.Values {
				e, perr := value.FromString(s, *want.Elem, r.cfg.Hosts, l)
				if perr != nil {
					return nil, perr
				}
				elems = append(elems, e)
			}
			v, err = value.List(*want.Elem, elems, l)
		}
		if err != nil {
			return nil, err
		}
		out[d.Name] = v
	}
	return out, nil
}

// Accept verifies an envelope and commits it: CommitHandoff re-checks
// closure and expiry, spends the handoff allowance, and calls install in one
// critical section; then the replay table records the result. install is
// the only place staged values enter a run.
func (r *Receiver) Accept(_ context.Context, body []byte, install func(*Staged)) (Response, *Staged) {
	now := r.cfg.Clock.Now()
	st, err := r.Verify(body, now)
	if err != nil {
		return r.reject(body, err), nil
	}
	k := runstate.HandoffKey{From: st.Payload.From, To: r.cfg.Self, Task: st.Payload.Task}
	if err := st.Run.CommitHandoff(k, func() { install(st) }, now); err != nil {
		r.cfg.Replay.Finish(st.Payload.From, st.Payload.ID, value.CodeOf(err))
		return r.reject(body, err), nil
	}
	if err := r.cfg.Replay.Finish(st.Payload.From, st.Payload.ID, ""); err != nil {
		// The entry was claimed by this call; failing to record it is a
		// bug, and the values are already installed, so say so loudly.
		r.cfg.Events.Emit(events.Event{Run: st.Ctx.RunID, Agent: r.cfg.Self, Kind: events.KindHandoffReject, Code: "ERR_REPLAY_TABLE", Detail: err.Error()})
	}
	r.cfg.Events.Emit(events.Event{Run: st.Ctx.RunID, Agent: r.cfg.Self, Kind: events.KindHandoffAccept,
		Handoff: handoffInfo(&st.Payload, st.Bytes, "accepted"), Detail: "values imported untrusted"})
	return Response{Status: "accepted", Run: st.Ctx.RunID}, st
}

func (r *Receiver) reject(body []byte, err error) Response {
	code := value.CodeOf(err)
	if code == "" {
		code = string(value.ErrSchema)
	}
	resp := Response{Status: "rejected", Code: code}
	var rec *runstate.RecordedError
	if errors.As(err, &rec) {
		resp.Recorded = rec.Prior.State.String()
	}
	r.cfg.Events.Emit(events.Event{Agent: r.cfg.Self, Kind: events.KindHandoffReject, Code: code,
		Detail: value.Truncate(err.Error()), Handoff: &events.HandoffInfo{Bytes: len(body), Status: "rejected"}})
	return resp
}

func handoffInfo(p *Payload, n int, status string) *events.HandoffInfo {
	info := &events.HandoffInfo{ID: p.ID, From: p.From, To: p.To, Task: p.Task, Bytes: n, Status: status}
	for _, d := range p.Data {
		info.Data = append(info.Data, d.Name+":"+d.Type)
	}
	return info
}
