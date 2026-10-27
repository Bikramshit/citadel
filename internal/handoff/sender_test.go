package handoff_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"testing"
	"time"

	"citadel/internal/authz"
	"citadel/internal/handoff"
	"citadel/internal/label"
	"citadel/internal/runstate"
	"citadel/internal/signed"
	"citadel/internal/value"
)

type flaky struct {
	inner  handoff.Transport
	fail   int
	bodies [][]byte
}

func (f *flaky) Deliver(ctx context.Context, to string, body []byte) (handoff.Response, error) {
	f.bodies = append(f.bodies, bytes.Clone(body))
	if f.fail > 0 {
		f.fail--
		return handoff.Response{}, errors.New("connection reset")
	}
	return f.inner.Deliver(ctx, to, body)
}

func (r *rig) sender(t *testing.T, tr handoff.Transport) *handoff.Sender {
	s, err := handoff.NewSender(handoff.SenderConfig{Self: "investigator", Signer: r.inv, Clock: r.clock, Rand: &deterministicReader{n: 100},
		Transport: tr, Lifetime: 2 * time.Minute, Retransmits: 2, Events: r.rec,
		ReceiverOps: func(to, task string, version int, params map[string]json.RawMessage) ([]authz.Cap, error) {
			return r.task.Ops(to, params)
		}})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func (r *rig) senderRun(t *testing.T) *runstate.RunState {
	rs, err := runstate.NewRuns("investigator", t0.Add(-time.Minute)).Activate(r.minted.Context, [32]byte{}, r.clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	return rs
}

func ipList(t *testing.T, ips ...string) value.Value {
	l := label.New(label.QLLM("investigator"), label.Tool("logs.read"))
	var elems []value.Value
	for _, s := range ips {
		v, err := value.FromString(s, value.Scalar(value.KindIPv4), nil, l)
		if err != nil {
			t.Fatal(err)
		}
		elems = append(elems, v)
	}
	v, err := value.List(value.Scalar(value.KindIPv4), elems, l)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func (r *rig) request(rs *runstate.RunState, data map[string]value.Value) handoff.Request {
	ops, _ := r.task.Ops("investigator", r.minted.Context.Params)
	return handoff.Request{Run: rs, Ctx: r.minted.Context, CtxWire: r.minted.Wire, Eff: ops, PC: label.New(label.Runtime()),
		Trust: label.DefaultTrust(), To: "responder", Task: "contain_incident", Data: data}
}

func TestSenderRetransmitsIdenticalBytes(t *testing.T) {
	r := newRig(t, nil)
	mem := handoff.NewMemTransport()
	mem.Register("responder", func(ctx context.Context, body []byte) handoff.Response {
		resp, _ := r.accept(body)
		return resp
	})
	tr := &flaky{inner: mem, fail: 1}
	s := r.sender(t, tr)
	sent, err := s.Send(context.Background(), r.request(r.senderRun(t), map[string]value.Value{"ips": ipList(t, "203.0.113.7")}))
	if err != nil || !sent.Response.Accepted() {
		t.Fatalf("send: %+v %v", sent, err)
	}
	if len(tr.bodies) != 2 || !bytes.Equal(tr.bodies[0], tr.bodies[1]) {
		t.Fatal("a retransmission must resend identical bytes")
	}
	// A third delivery of the same bytes is answered with the recorded result.
	resp, _ := r.accept(sent.Bytes)
	if resp.Accepted() || resp.Recorded != "accepted" || r.installs != 1 {
		t.Fatalf("recorded result: %+v", resp)
	}
}

func TestSenderRefusalsSendNothing(t *testing.T) {
	r := newRig(t, nil)
	mem := handoff.NewMemTransport()
	tr := &flaky{inner: mem}
	s := r.sender(t, tr)
	rs := r.senderRun(t)
	req := r.request(rs, map[string]value.Value{"ips": ipList(t, "203.0.113.7")})
	req.RequestedOps = []authz.Op{{Tool: "firewall", Action: "allow"}}
	if _, err := s.Send(context.Background(), req); !errors.Is(err, value.ErrExcessGrant) {
		t.Fatalf("D2 / H2: %v", err)
	}
	req = r.request(rs, map[string]value.Value{"ips": ipList(t, "203.0.113.7")})
	req.To = "auditor"
	if _, err := s.Send(context.Background(), req); !errors.Is(err, value.ErrNoHandoffCap) {
		t.Fatalf("D5 / H1: %v", err)
	}
	req = r.request(rs, map[string]value.Value{"ips": ipList(t, "203.0.113.7")})
	req.PC = label.New(label.QLLM("investigator"))
	if _, err := s.Send(context.Background(), req); !errors.Is(err, value.ErrUntrustedPC) {
		t.Fatalf("H3: %v", err)
	}
	var many []string
	for i := 0; i < 51; i++ {
		many = append(many, "203.0.113."+strconv.Itoa(i+1))
	}
	if _, err := s.Send(context.Background(), r.request(rs, map[string]value.Value{"ips": ipList(t, many...)})); !errors.Is(err, value.ErrType) {
		t.Fatalf("51 values: %v", err)
	}
	b := value.Bool(true, label.New(label.Runtime()))
	if _, err := s.Send(context.Background(), r.request(rs, map[string]value.Value{"ips": b})); !errors.Is(err, value.ErrType) {
		t.Fatalf("non-list data: %v", err)
	}
	if len(tr.bodies) != 0 {
		t.Fatal("a refused handoff must send nothing")
	}
	// The allowance is spent once: a second send in the run is refused.
	mem.Register("responder", func(ctx context.Context, body []byte) handoff.Response { return handoff.Response{Status: "accepted"} })
	if _, err := s.Send(context.Background(), r.request(rs, map[string]value.Value{"ips": ipList(t, "203.0.113.7")})); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Send(context.Background(), r.request(rs, map[string]value.Value{"ips": ipList(t, "203.0.113.8")})); !errors.Is(err, value.ErrWorkflow) {
		t.Fatalf("second send: %v", err)
	}
	dead := r.sender(t, &flaky{inner: mem, fail: 10})
	if _, err := dead.Send(context.Background(), r.request(r.senderRun(t), map[string]value.Value{"ips": ipList(t, "203.0.113.7")})); err == nil {
		t.Fatal("persistent transport failure must error")
	}
}

func TestNewSenderValidation(t *testing.T) {
	r := newRig(t, nil)
	base := handoff.SenderConfig{Self: "investigator", Signer: r.inv, Clock: r.clock, Rand: &deterministicReader{}, Transport: handoff.NewMemTransport(),
		Lifetime: time.Minute, Events: r.rec, ReceiverOps: func(string, string, int, map[string]json.RawMessage) ([]authz.Cap, error) { return nil, nil }}
	bad := []func(*handoff.SenderConfig){
		func(c *handoff.SenderConfig) { c.Signer = nil },
		func(c *handoff.SenderConfig) { c.Lifetime = 6 * time.Minute },
		func(c *handoff.SenderConfig) { c.Retransmits = -1 },
		func(c *handoff.SenderConfig) { c.Signer = r.resp },
	}
	for i, m := range bad {
		c := base
		m(&c)
		if _, err := handoff.NewSender(c); !errors.Is(err, value.ErrConfig) {
			t.Errorf("mutation %d accepted", i)
		}
	}
	if _, err := handoff.NewID(&deterministicReader{}); err != nil {
		t.Fatal(err)
	}
}

func TestClaimsOfAndSchema(t *testing.T) {
	l := label.New(label.Peer("x", "y"), label.Claimed("tool:logs.read"), label.QLLM("investigator"), label.Runtime())
	got := handoff.ClaimsOf(l)
	if len(got) != 2 || got[0] != "qllm:investigator" || got[1] != "runtime" {
		t.Fatalf("claims %v", got)
	}
	r := newRig(t, nil)
	if s := handoff.DataSchema(r.task, handoff.ModeC2); len(s) != 2 {
		t.Fatal("C2 schema")
	}
	if s := handoff.DataSchema(r.task, handoff.ModeC1Instr); s["report"].Kind != value.KindText {
		t.Fatal("C1 schema")
	}
}

func FuzzDecodeOuter(f *testing.F) {
	r := newRig(f, nil)
	f.Add(r.envelope(r.payload()))
	f.Add([]byte(`{"payload":"x","kid":"k","sig":"s","x":1}`))
	f.Add([]byte(`[]`))
	f.Fuzz(func(t *testing.T, body []byte) {
		w, err := signed.DecodeWire(body, handoff.MaxBody)
		if err != nil {
			if value.CodeOf(err) == "" {
				t.Fatalf("error without a code: %v", err)
			}
			return
		}
		if w.Payload == "" || w.KID == "" || w.Sig == "" {
			t.Fatal("accepted an incomplete wire object")
		}
	})
}

func FuzzDecodePayload(f *testing.F) {
	r := newRig(f, nil)
	f.Add(payloadBytes(f, r.payload()))
	f.Add([]byte(`{"v":1,"v":2}`))
	f.Add([]byte(`{"v":1,"V":2}`))
	f.Fuzz(func(t *testing.T, p []byte) {
		var out handoff.Payload
		err := value.DecodeStrict(p, &out, value.Limits{MaxBytes: handoff.MaxBody, MaxDepth: 8})
		if err != nil {
			if value.CodeOf(err) == "" {
				t.Fatalf("error without a code: %v", err)
			}
			return
		}
		var m map[string]json.RawMessage
		if json.Unmarshal(p, &m) == nil {
			seen := map[string]bool{}
			for k := range m {
				lk := string(bytes.ToLower([]byte(k)))
				if seen[lk] {
					t.Fatalf("accepted duplicate key %q", k)
				}
				seen[lk] = true
			}
		}
	})
}

// Any changed byte of a valid envelope must be rejected.
func FuzzVerifyMutatedEnvelope(f *testing.F) {
	r := newRig(f, nil)
	body := r.envelope(r.payload())
	if _, err := r.rcv.Verify(body, r.clock.Now()); err != nil {
		f.Fatalf("seed envelope must verify: %v", err)
	}
	f.Add(uint16(0), byte('x'))
	f.Add(uint16(20), byte('A'))
	f.Add(uint16(len(body)-5), byte('B'))
	f.Fuzz(func(t *testing.T, pos uint16, b byte) {
		i := int(pos) % len(body)
		if body[i] == b {
			return
		}
		m := bytes.Clone(body)
		m[i] = b
		if st, err := r.rcv.Verify(m, r.clock.Now()); err == nil {
			t.Fatalf("mutated envelope accepted: byte %d %q -> %q (run %s)", i, body[i], b, st.Ctx.RunID)
		}
	})
}
