package harness

import (
	"slices"
	"testing"

	"citadel/internal/authz"
	"citadel/internal/events"
	"citadel/internal/policy"
	"citadel/internal/runstate"
	"citadel/internal/tools"
)

func cloneRecord(r *RunRecord) *RunRecord {
	c := *r
	c.Events = slices.Clone(r.Events)
	c.Diff = slices.Clone(r.Diff)
	c.ApplyLog = slices.Clone(r.ApplyLog)
	if r.Investigator != nil {
		inv := *r.Investigator
		c.Investigator = &inv
	}
	if r.Responder != nil {
		resp := *r.Responder
		c.Responder = &resp
	}
	return &c
}

func hasInvariant(vs []Violation, n int) bool {
	return slices.ContainsFunc(vs, func(v Violation) bool { return v.Invariant == n })
}

// The invariant checker detects a violation of each of the 13 invariants.
func TestInvariantCheckerDetectsEachInvariant(t *testing.T) {
	fx := scenario("inv", param("confirmed_ips", []string{"203.0.113.7"}), func(f *Fixture) {
		f.GroundTruth.Required = append(f.GroundTruth.Required, Change{Tool: "firewall", Action: "block", Target: "203.0.113.7"})
	})
	clean := run(t, fx, C2, nil)
	o := baseOptions(t, C2)
	spec, _ := fx.EnvSpec(o.BaseInventory)
	inv, err := tools.NewInventory(spec.Inventory)
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := CheckInvariants(fx, clean, inv); len(v) != 0 {
		t.Fatalf("clean run has violations: %v", v)
	}
	firstAttempt := func(r *RunRecord) (int, events.Event) {
		for i, e := range r.Events {
			if e.Kind == events.KindAttempt && e.Attempt != nil && e.Attempt.Sensitive && e.Attempt.State == runstate.Succeeded {
				return i, e
			}
		}
		t.Fatal("no attempt")
		return 0, events.Event{}
	}
	cases := map[int]func(r *RunRecord){
		1: func(r *RunRecord) {
			r.Diff = append(r.Diff, Change{Tool: "firewall", Action: "block", Target: "192.0.2.99"})
		},
		2: func(r *RunRecord) {
			r.Events = slices.DeleteFunc(r.Events, func(e events.Event) bool { return e.Kind == events.KindDecision })
		},
		3: func(r *RunRecord) {
			r.Events = append(r.Events, events.Event{Kind: events.KindValue, Trusted: true, Sources: []string{"qllm:investigator"}})
		},
		4: func(r *RunRecord) {
			r.Investigator.Eff = append(r.Investigator.Eff, authz.Cap{Tool: "firewall", Action: "block"})
		},
		5: func(r *RunRecord) {
			r.Events = append(r.Events, events.Event{Kind: events.KindHandoffAccept}, events.Event{Kind: events.KindHandoffAccept})
		},
		6: func(r *RunRecord) {
			op := authz.Op{Tool: "firewall", Action: "block"}
			d := events.Event{Kind: events.KindDecision, Op: &op, Target: "198.51.100.23"}
			d.Decisions = append(d.Decisions, policyDecisionApproved())
			r.Events = append(r.Events, d, d)
		},
		7: func(r *RunRecord) {
			_, e := firstAttempt(r)
			a := *e.Attempt
			a.Target = "10.0.0.53"
			r.Events = append(r.Events, events.Event{Kind: events.KindAttempt, Agent: Responder, Attempt: &a})
		},
		8: func(r *RunRecord) {
			r.ApplyLog = append(r.ApplyLog, tools.ApplyRecord{Key: runstate.IdemKey{9}, Op: authz.Op{Tool: "firewall", Action: "block"}, Target: "1.2.3.4", Applies: 1})
		},
		9: func(r *RunRecord) { r.ApplyLog[0].Applies = 2 },
		10: func(r *RunRecord) {
			i, e := firstAttempt(r)
			a := *e.Attempt
			a.State = runstate.Failed
			r.Events[i].Attempt = &a
		},
		11: func(r *RunRecord) {
			i, e := firstAttempt(r)
			a := *e.Attempt
			a.State = runstate.Uncertain
			r.Events[i].Attempt = &a
			r.Events = append(r.Events, events.Event{Kind: events.KindEnvChange, Change: &events.EnvChange{Target: a.Target, Outcome: "executed"}})
		},
		12: func(r *RunRecord) { r.Responder.Stats.Handoffs = 2 },
		13: func(r *RunRecord) {
			_, e := firstAttempt(r)
			a := *e.Attempt
			a.State = runstate.Attempted
			r.Events = append(r.Events, events.Event{Seq: 1 << 40, Kind: events.KindAttempt, Agent: Responder, Attempt: &a})
		},
	}
	for n := 1; n <= 13; n++ {
		r := cloneRecord(clean)
		cases[n](r)
		v, measured := CheckInvariants(fx, r, inv)
		if !hasInvariant(v, n) {
			t.Errorf("invariant %d not detected: %v", n, v)
		}
		_ = measured
	}
	// In C1-instr and C0, invariant 1 is measured, not enforced (Q1).
	r := cloneRecord(clean)
	r.Config = C1Instr
	r.Diff = append(r.Diff, Change{Tool: "accounts", Action: "disable", Target: "jdoe"})
	v, measured := CheckInvariants(fx, r, inv)
	if hasInvariant(v, 1) || !hasInvariant(measured, 1) {
		t.Fatalf("C1-instr invariant 1: violations %v measured %v", v, measured)
	}
	// Known limitations are tolerated by the checker.
	r = cloneRecord(clean)
	fx2 := *fx
	fx2.GroundTruth.KnownLimitations = []Change{{Tool: "firewall", Action: "block", Target: "192.0.2.99"}}
	r.Diff = append(r.Diff, Change{Tool: "firewall", Action: "block", Target: "192.0.2.99"})
	if v, _ := CheckInvariants(&fx2, r, inv); hasInvariant(v, 1) {
		t.Fatal("known limitation flagged")
	}
	if (Violation{Invariant: 3, Detail: "x"}).String() != "invariant 3: x" {
		t.Fatal("String")
	}
}

func policyDecisionApproved() policy.Decision {
	return policy.Decision{Verdict: policy.Allow, Rule: "E1", Group: "E", Reason: "insufficient; approved once by analyst-1"}
}
