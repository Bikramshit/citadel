// Package handoff implements the typed, signed handoff between agents: the
// payload, the sender's checks (H1 to H3), the receiver's eleven steps in
// order (H4 to H6), and staged, atomic import. A handoff carries a task
// request (instruction channel) and typed values (data channel), and has no
// free-text field at all. Every data value arrives untrusted, whatever
// sources the sender claims: the receiver labels each one Peer(from, id)
// plus the claimed sources, kept for audit.
package handoff

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"citadel/internal/authz"
	"citadel/internal/catalog"
	"citadel/internal/label"
	"citadel/internal/signed"
	"citadel/internal/value"
)

// Limits from the specification.
const (
	Version     = 1
	MaxBody     = 64 << 10        // body at most 64 KiB
	MaxValues   = 50              // at most 50 values per list
	MaxString   = 256             // strings at most 256 bytes (the embedded context token excepted)
	MaxLifetime = 5 * time.Minute // lifetime at most 5 minutes
	MaxFuture   = 30 * time.Second
	Skew        = 30 * time.Second // replay entries live until expires_at plus skew
)

// Comparison modes. C2 is the typed handoff. C1-instr and C1-data carry a
// free-text report instead, for the evaluation only.
const (
	ModeC2      = "C2"
	ModeC1Instr = "C1-instr"
	ModeC1Data  = "C1-data"
)

// ReportData is the single data item of the C1 comparison handoffs.
const ReportData = "report"

// DataItem is one named, typed list with the sources the sender claims.
type DataItem struct {
	Name           string   `json:"name"`
	Type           string   `json:"type"` // list<ipv4> | list<account_id> | text (C1 only)
	Values         []string `json:"values"`
	ClaimedSources []string `json:"claimed_sources"`
}

// Payload is the exact JSON the sender signs.
type Payload struct {
	V            int         `json:"v"`
	KID          string      `json:"kid"`
	ID           string      `json:"id"`
	RunID        string      `json:"run_id"`
	From         string      `json:"from"`
	To           string      `json:"to"`
	Task         string      `json:"task"`
	TaskVersion  int         `json:"task_version"`
	RequestedOps []authz.Op  `json:"requested_ops"`
	IssuedAt     time.Time   `json:"issued_at"`
	ExpiresAt    time.Time   `json:"expires_at"`
	AuthCtx      signed.Wire `json:"authctx"`
	Data         []DataItem  `json:"data"`
}

// Response is the receiver's answer.
type Response struct {
	Status   string `json:"status"` // accepted | rejected
	Code     string `json:"code,omitempty"`
	Recorded string `json:"recorded,omitempty"` // for an identical retransmission: the recorded result
	Run      string `json:"run,omitempty"`
}

// Accepted reports whether the envelope was accepted now.
func (r Response) Accepted() bool { return r.Status == "accepted" }

// DataSchema returns the data items a handoff in mode may carry.
func DataSchema(task *catalog.Task, mode string) map[string]value.Type {
	if mode == ModeC1Instr || mode == ModeC1Data {
		return map[string]value.Type{ReportData: value.Scalar(value.KindText)}
	}
	out := map[string]value.Type{}
	for _, n := range task.DataNames() {
		out[n], _ = task.DataType(n)
	}
	return out
}

// CheckSend runs the sender's rules before anything is signed. H1: the
// sender holds handoff.request for this receiver and task, and the workflow
// lists it. H2: requested operations are within the receiver's run grant ∩
// task operations, not the sender's capabilities. H3: no handoff under
// untrusted pc.
func CheckSend(ac *authz.AuthContext, eff []authz.Cap, from, to, task string, requested []authz.Op, pc label.Label, tt label.TrustTable, receiverTaskOps []authz.Cap) error {
	if !authz.Covers(eff, authz.HandoffCap(to, task)) || !ac.WorkflowAllows(from, to, task) {
		return fmt.Errorf("%w: H1: no handoff capability or workflow entry for %s -> %s %s", value.ErrNoHandoffCap, from, value.Truncate(to), value.Truncate(task)) // H1
	}
	if requested != nil && !authz.OpsSubsetOf(requested, authz.Intersect(ac.Grants[to], receiverTaskOps)) {
		return fmt.Errorf("%w: H2: requested operations exceed %s's run grant", value.ErrExcessGrant, to) // H2: checked against the run grant, not the sender's caps
	}
	if !pc.Trusted(tt) {
		return fmt.Errorf("%w: H3: handoff inside a loop over untrusted data", value.ErrUntrustedPC) // H3
	}
	return nil
}

// Transport delivers envelope bytes to an agent.
type Transport interface {
	Deliver(ctx context.Context, to string, body []byte) (Response, error)
}

// MemTransport delivers in-process to registered handlers, passing the same
// signed bytes through the same Verify as HTTP.
type MemTransport struct {
	mu       sync.Mutex
	handlers map[string]func(ctx context.Context, body []byte) Response
}

// NewMemTransport returns an empty in-process transport.
func NewMemTransport() *MemTransport {
	return &MemTransport{handlers: map[string]func(context.Context, []byte) Response{}}
}

// Register attaches agent's receiving handler.
func (t *MemTransport) Register(agent string, h func(ctx context.Context, body []byte) Response) {
	t.mu.Lock()
	t.handlers[agent] = h
	t.mu.Unlock()
}

// Deliver hands a copy of body to the recipient's handler.
func (t *MemTransport) Deliver(ctx context.Context, to string, body []byte) (Response, error) {
	t.mu.Lock()
	h, ok := t.handlers[to]
	t.mu.Unlock()
	if !ok {
		return Response{}, fmt.Errorf("handoff: no agent %q on this transport", value.Truncate(to))
	}
	return h(ctx, bytes.Clone(body)), nil
}

// HTTPTransport posts envelopes to agents' /v1/handoff endpoints.
type HTTPTransport struct {
	Client *http.Client
	Peers  map[string]string // agent -> base URL, http://127.0.0.1:port
}

// Deliver posts body and decodes the response strictly.
func (t *HTTPTransport) Deliver(ctx context.Context, to string, body []byte) (Response, error) {
	base, ok := t.Peers[to]
	if !ok {
		return Response{}, fmt.Errorf("handoff: no address for agent %q", value.Truncate(to))
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/v1/handoff", bytes.NewReader(body))
	if err != nil {
		return Response{}, fmt.Errorf("handoff: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := t.Client.Do(req)
	if err != nil {
		return Response{}, fmt.Errorf("handoff: post: %w", err)
	}
	defer resp.Body.Close()
	rb, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return Response{}, fmt.Errorf("handoff: read response: %w", err)
	}
	var r Response
	if err := value.DecodeStrict(rb, &r, value.Limits{MaxBytes: 4096}); err != nil {
		return Response{}, fmt.Errorf("handoff: response: %w", err)
	}
	return r, nil
}

// HTTPHandler serves POST /v1/handoff with accept. Bodies are limited with
// http.MaxBytesReader; an oversized body is rejected with ERR_SIZE before
// anything is parsed.
func HTTPHandler(accept func(ctx context.Context, body []byte) Response) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxBody))
		var resp Response
		if err != nil {
			resp = Response{Status: "rejected", Code: string(value.ErrSize)}
		} else {
			resp = accept(r.Context(), body)
		}
		w.Header().Set("Content-Type", "application/json")
		if !resp.Accepted() && resp.Recorded == "" {
			w.WriteHeader(http.StatusUnprocessableEntity)
		}
		b, _ := json.Marshal(resp) // Response always marshals
		w.Write(b)
	})
}

// knownClaims returns the fixed list of source names a peer may claim.
func knownClaims(ac *authz.AuthContext, task *catalog.Task) map[string]bool {
	m := map[string]bool{
		label.Tool("logs.read").String(): true, label.Tool("inventory.read").String(): true,
		label.Runtime().String(): true, label.UserNote().String(): true,
	}
	for _, a := range ac.Agents {
		m[label.QLLM(a).String()] = true
		m[label.PlannerLiteral(a).String()] = true
	}
	for _, p := range task.ParamNames() {
		m[label.TaskParam(p).String()] = true
	}
	return m
}

// ClaimsOf renders a value's sources as the claims a sender puts on the wire.
// Peer sources from earlier hops are dropped: they cannot be claimed, and the
// receiver adds its own Peer source anyway.
func ClaimsOf(l label.Label) []string {
	var out []string
	for _, s := range l.Sources() {
		if s.Kind == label.SrcPeer || s.Kind == label.SrcClaimed {
			continue
		}
		out = append(out, s.String())
	}
	slices.Sort(out)
	return out
}

// payloadDigest hashes the exact payload bytes.
func payloadDigest(p []byte) [32]byte { return sha256.Sum256(p) }

func checkStrings(p *Payload) error {
	strs := []string{p.KID, p.ID, p.RunID, p.From, p.To, p.Task, p.AuthCtx.KID}
	for _, op := range p.RequestedOps {
		strs = append(strs, op.Tool, op.Action)
	}
	for _, d := range p.Data {
		strs = append(strs, d.Name, d.Type)
		strs = append(strs, d.ClaimedSources...)
		if d.Type != "text" {
			strs = append(strs, d.Values...)
		}
	}
	for _, s := range strs {
		if len(s) > MaxString {
			return fmt.Errorf("%w: a payload string exceeds %d bytes", value.ErrSchema, MaxString)
		}
	}
	return nil
}

func validID(id string) bool {
	if len(id) != 22 {
		return false
	}
	return !strings.ContainsFunc(id, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_')
	})
}
