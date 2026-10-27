package handoff

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"slices"
	"time"

	"citadel/internal/authz"
	"citadel/internal/events"
	"citadel/internal/label"
	"citadel/internal/runstate"
	"citadel/internal/signed"
	"citadel/internal/value"
)

// SenderConfig configures a Sender.
type SenderConfig struct {
	Self           string
	Signer         *signed.Signer
	Clock          value.Clock
	Rand           io.Reader // crypto/rand.Reader outside tests
	Transport      Transport
	Lifetime       time.Duration // at most MaxLifetime
	Retransmits    int           // identical-bytes resends after a transport error
	Events         events.Sink
	ReceiverOps    func(to, task string, version int, params map[string]json.RawMessage) ([]authz.Cap, error)
	ConfigName     string
	ReportMaxBytes int
}

// Sender builds, signs, and sends envelopes. The runtime, not a model, builds
// the payload.
type Sender struct {
	cfg SenderConfig
}

// NewSender validates cfg.
func NewSender(cfg SenderConfig) (*Sender, error) {
	if cfg.Self == "" || cfg.Signer == nil || cfg.Clock == nil || cfg.Rand == nil || cfg.Transport == nil || cfg.Events == nil || cfg.ReceiverOps == nil {
		return nil, fmt.Errorf("%w: sender configuration incomplete", value.ErrConfig)
	}
	if cfg.Lifetime <= 0 || cfg.Lifetime > MaxLifetime || cfg.Retransmits < 0 {
		return nil, fmt.Errorf("%w: envelope lifetime must be in (0, %s]", value.ErrConfig, MaxLifetime)
	}
	if cfg.Signer.Agent() != cfg.Self {
		return nil, fmt.Errorf("%w: signer belongs to %s, not %s", value.ErrConfig, cfg.Signer.Agent(), cfg.Self)
	}
	return &Sender{cfg: cfg}, nil
}

// Request is one handoff the interpreter asks the runtime to send.
type Request struct {
	Run          *runstate.RunState
	Ctx          *authz.AuthContext
	CtxWire      signed.Wire
	Eff          []authz.Cap
	PC           label.Label
	Trust        label.TrustTable
	To, Task     string
	RequestedOps []authz.Op
	Data         map[string]value.Value
}

// Sent describes a delivered envelope.
type Sent struct {
	ID       string
	Bytes    []byte
	Response Response
}

// NewID returns 128 random bits, base64url: an envelope ID that is also the
// nonce.
func NewID(r io.Reader) (string, error) {
	var b [16]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return "", fmt.Errorf("handoff: random id: %w", err)
	}
	return signed.EncodeBase64(b[:]), nil
}

// Send checks H1 to H3, reserves the handoff allowance, builds and signs the
// payload, and delivers it. A transport error resends the identical bytes, so
// the receiver's replay table answers with the recorded result instead of
// importing twice. A refusal sends nothing.
func (s *Sender) Send(ctx context.Context, req Request) (Sent, error) {
	recv, err := s.cfg.ReceiverOps(req.To, req.Task, req.Ctx.TaskVersion, req.Ctx.Params)
	if err != nil {
		recv = nil
	}
	if err := CheckSend(req.Ctx, req.Eff, s.cfg.Self, req.To, req.Task, req.RequestedOps, req.PC, req.Trust, recv); err != nil {
		return Sent{}, err
	}
	items, err := s.items(req.Data)
	if err != nil {
		return Sent{}, err
	}
	now := s.cfg.Clock.Now()
	if err := req.Run.ReserveHandoff(runstate.HandoffKey{From: s.cfg.Self, To: req.To, Task: req.Task}, now); err != nil {
		return Sent{}, err
	}
	id, err := NewID(s.cfg.Rand)
	if err != nil {
		return Sent{}, err
	}
	p := Payload{V: Version, KID: s.cfg.Signer.KID(), ID: id, RunID: req.Ctx.RunID, From: s.cfg.Self, To: req.To,
		Task: req.Task, TaskVersion: req.Ctx.TaskVersion, RequestedOps: req.RequestedOps,
		IssuedAt: now, ExpiresAt: now.Add(s.cfg.Lifetime), AuthCtx: req.CtxWire, Data: items}
	pb, err := json.Marshal(p)
	if err != nil {
		return Sent{}, fmt.Errorf("handoff: encode payload: %w", err)
	}
	body := signed.EncodeWire(s.cfg.Signer.Sign(signed.PrefixHandoff, pb))
	s.cfg.Events.Emit(events.Event{Run: req.Ctx.RunID, Config: s.cfg.ConfigName, Agent: s.cfg.Self, Kind: events.KindHandoffSend,
		PCTrusted: req.PC.Trusted(req.Trust), Handoff: handoffInfo(&p, len(body), "sent")})
	var resp Response
	for attempt := 0; ; attempt++ {
		resp, err = s.cfg.Transport.Deliver(ctx, req.To, body)
		if err == nil || attempt >= s.cfg.Retransmits {
			break
		}
	}
	if err != nil {
		return Sent{ID: id, Bytes: body}, fmt.Errorf("handoff: deliver after %d retransmissions: %w", s.cfg.Retransmits, err)
	}
	return Sent{ID: id, Bytes: body, Response: resp}, nil
}

// items renders typed values as data items with their claimed sources.
func (s *Sender) items(data map[string]value.Value) ([]DataItem, error) {
	var out []DataItem
	for _, name := range slices.Sorted(maps.Keys(data)) {
		v := data[name]
		d := DataItem{Name: name, Type: v.Type().String(), ClaimedSources: ClaimsOf(v.Label())}
		switch v.Kind() {
		case value.KindList:
			if v.Count() > MaxValues {
				return nil, fmt.Errorf("%w: data %q has %d values, limit %d", value.ErrType, name, v.Count(), MaxValues)
			}
			for _, e := range v.Elems() {
				d.Values = append(d.Values, e.Canonical())
				for _, c := range ClaimsOf(e.Label()) {
					if !slices.Contains(d.ClaimedSources, c) {
						d.ClaimedSources = append(d.ClaimedSources, c)
					}
				}
			}
			slices.Sort(d.ClaimedSources)
		case value.KindText:
			d.Values = []string{v.Canonical()}
		default:
			return nil, fmt.Errorf("%w: data %q of type %s cannot cross a handoff", value.ErrType, name, v.Type())
		}
		if d.Values == nil {
			d.Values = []string{}
		}
		if d.ClaimedSources == nil {
			d.ClaimedSources = []string{}
		}
		out = append(out, d)
	}
	return out, nil
}
