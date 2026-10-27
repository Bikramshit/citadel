package evidence

import (
	"fmt"
	"net/netip"
	"slices"
	"testing"
	"time"
)

var now = time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)

type reg struct {
	shared  []netip.Addr
	sensors []Sensor
}

func (r reg) IsPartnerOrShared(a netip.Addr) bool { return slices.Contains(r.shared, a) }
func (r reg) Sensors() []Sensor                   { return r.sensors }

func baseReg() reg {
	return reg{shared: []netip.Addr{netip.MustParseAddr("192.0.2.10")}, sensors: []Sensor{
		{ID: "web-access", Kind: "access", Pipeline: "web-logs"},
		{ID: "net-flows", Kind: "flow", Pipeline: "netflow"},
	}}
}

func fail(ip string, n int, prefix string) []AccessRecord {
	out := make([]AccessRecord, n)
	for i := range out {
		out[i] = AccessRecord{EventID: fmt.Sprintf("%s%d", prefix, i), TS: now.Add(-time.Duration(30-i) * time.Minute), Host: "web-03",
			ClientIP: netip.MustParseAddr(ip), Status: 401, AuthResult: "fail", SensorID: "web-access", PipelineID: "web-logs"}
	}
	return out
}

func fl(ip, state, sensor, pipe string) FlowRecord {
	return FlowRecord{FlowID: "f-" + ip + state + sensor, TS: now.Add(-10 * time.Minute), SrcIP: netip.MustParseAddr(ip), DstHost: "web-03",
		State: state, SensorID: sensor, PipelineID: pipe}
}

var sc = TaskScope{Hosts: []string{"web-03"}, From: now.Add(-time.Hour), To: now, LoginPath: "/login"}
var th = Thresholds{K: 5, MinFlows: 1}

func mustStore(t *testing.T, r Registry, a []AccessRecord, f []FlowRecord) *Store {
	t.Helper()
	s, err := NewStore(r, a, f)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestVerdictOrder(t *testing.T) {
	x := netip.MustParseAddr("198.51.100.23")
	cases := []struct {
		name   string
		access []AccessRecord
		flows  []FlowRecord
		addr   netip.Addr
		want   EvidenceVerdict
	}{
		{"corroborated", fail("198.51.100.23", 6, "a"), []FlowRecord{fl("198.51.100.23", FlowEstablished, "net-flows", "netflow")}, x, EvCorroborated},
		{"absent", nil, nil, x, EvAbsent},
		{"shared first", fail("192.0.2.10", 6, "s"), []FlowRecord{fl("192.0.2.10", FlowEstablished, "net-flows", "netflow")}, netip.MustParseAddr("192.0.2.10"), EvConflict},
		{"sensor disagreement", fail("198.51.100.23", 6, "a"), []FlowRecord{fl("203.0.113.1", FlowEstablished, "net-flows", "netflow")}, x, EvConflict},
		{"too few", fail("198.51.100.23", 4, "a"), []FlowRecord{fl("198.51.100.23", FlowEstablished, "net-flows", "netflow")}, x, EvInsufficient},
		{"no flow data", fail("198.51.100.23", 6, "a"), nil, x, EvInsufficient},
		{"syn only", fail("198.51.100.23", 6, "a"), []FlowRecord{fl("198.51.100.23", FlowSynOnly, "net-flows", "netflow")}, x, EvInsufficient},
		{"flow from an access pipeline", fail("198.51.100.23", 6, "a"), []FlowRecord{fl("198.51.100.23", FlowEstablished, "net-flows", "web-logs")}, x, EvInsufficient},
	}
	for _, c := range cases {
		s := mustStore(t, baseReg(), c.access, c.flows)
		if v, counts := s.CorroborateIP(c.addr, sc, th); v != c.want || counts.Verdict != c.want {
			t.Errorf("%s: got %s want %s (%+v)", c.name, v, c.want, counts)
		}
	}
}

func TestSignatureAndWindow(t *testing.T) {
	recs := fail("198.51.100.23", 3, "a")
	recs = append(recs,
		AccessRecord{EventID: "p1", TS: now.Add(-time.Minute), Host: "web-03", ClientIP: netip.MustParseAddr("198.51.100.23"), Status: 403, Path: "/login", SensorID: "web-access", PipelineID: "web-logs"},
		AccessRecord{EventID: "p2", TS: now.Add(-2 * time.Minute), Host: "web-03", ClientIP: netip.MustParseAddr("198.51.100.23"), Status: 403, Path: "/other", SensorID: "web-access", PipelineID: "web-logs"},
		AccessRecord{EventID: "old", TS: now.Add(-2 * time.Hour), Host: "web-03", ClientIP: netip.MustParseAddr("198.51.100.23"), AuthResult: "fail", SensorID: "web-access", PipelineID: "web-logs"},
		AccessRecord{EventID: "w4", TS: now.Add(-time.Minute), Host: "web-04", ClientIP: netip.MustParseAddr("198.51.100.23"), AuthResult: "fail", SensorID: "web-access", PipelineID: "web-logs"},
	)
	s := mustStore(t, baseReg(), recs, nil)
	_, c := s.CorroborateIP(netip.MustParseAddr("198.51.100.23"), sc, th)
	if c.Observations != 4 {
		t.Fatalf("observations %d, want 3 failed + 1 403 on the login path", c.Observations)
	}
	if len(s.AllAccess()) != len(recs) || len(s.AllFlows()) != 0 {
		t.Fatal("All*")
	}
	if !sc.InWindow(now) || !sc.InWindow(now.Add(-time.Hour)) || sc.InWindow(now.Add(time.Second)) {
		t.Fatal("window bounds are inclusive")
	}
}

func TestAccountVerdicts(t *testing.T) {
	login := func(ip string) AccessRecord {
		return AccessRecord{EventID: "s-" + ip, TS: now.Add(-time.Minute), Host: "web-03", ClientIP: netip.MustParseAddr(ip), Status: 200,
			AuthResult: "success", AuthPrincipal: "svc-backup", SensorID: "web-access", PipelineID: "web-logs"}
	}
	attempt := fail("198.51.100.23", 1, "j")[0]
	attempt.AttemptedUser = "jdoe"
	recs := append(fail("198.51.100.23", 6, "a"), attempt, login("198.51.100.23"), login("203.0.113.50"))
	s := mustStore(t, baseReg(), recs, []FlowRecord{fl("198.51.100.23", FlowEstablished, "net-flows", "netflow")})
	if v, _ := s.CorroborateAccount("jdoe", sc, th); v != EvAbsent {
		t.Errorf("attempted_user must never count: %s", v)
	}
	if v, c := s.CorroborateAccount("svc-backup", sc, th); v != EvCorroborated || c.SuccessLogins != 2 || c.Observations != 6 {
		t.Errorf("svc-backup: %s %+v", v, c)
	}
	s = mustStore(t, baseReg(), []AccessRecord{login("203.0.113.50")}, nil)
	if v, _ := s.CorroborateAccount("svc-backup", sc, th); v != EvInsufficient {
		t.Errorf("login from an uncorroborated IP: %s", v)
	}
}

func TestIndependence(t *testing.T) {
	r := baseReg()
	r.sensors = append(r.sensors,
		Sensor{ID: "lb-flows", Kind: "flow", Pipeline: "lb", DerivedFrom: "lb-access"},
		Sensor{ID: "lb-access", Kind: "access", Pipeline: "lb"},
		Sensor{ID: "derived", Kind: "flow", Pipeline: "p2", DerivedFrom: "web-access"},
	)
	s := mustStore(t, r, fail("198.51.100.23", 1, "a"), nil)
	ind := s.IndependentOf("access", sc)
	if _, ok := ind.sensors["net-flows"]; !ok || len(ind.sensors) != 1 {
		t.Fatalf("independent sensors %v", ind.sensors)
	}
	if ind.counts(fl("1.2.3.4", FlowEstablished, "net-flows", "lb")) {
		t.Fatal("a record whose pipeline differs from its sensor's registration must not count")
	}
}

func TestTrustedDigest(t *testing.T) {
	a := fail("198.51.100.23", 1, "a")[0]
	b := a
	b.EventID, b.TS, b.PipelineID, b.UserAgent = "zz", a.TS.Add(300*time.Millisecond), "other", "x"
	if a.TrustedDigest() != b.TrustedDigest() {
		t.Fatal("digest must ignore event ID, sub-second time, pipeline, and attacker fields")
	}
	b.Status = 403
	if a.TrustedDigest() == b.TrustedDigest() {
		t.Fatal("digest must cover trusted fields")
	}
}

func TestValidate(t *testing.T) {
	good := fail("198.51.100.23", 1, "a")[0]
	bad := []func(*AccessRecord){
		func(r *AccessRecord) { r.EventID = "" },
		func(r *AccessRecord) { r.ClientIP = netip.MustParseAddr("::1") },
		func(r *AccessRecord) { r.TS = time.Time{} },
		func(r *AccessRecord) { r.AuthResult = "maybe" },
		func(r *AccessRecord) { r.AuthPrincipal = "jdoe" },
	}
	for i, m := range bad {
		r := good
		m(&r)
		if r.Validate() == nil {
			t.Errorf("access mutation %d accepted", i)
		}
		if _, err := NewStore(baseReg(), []AccessRecord{r}, nil); err == nil {
			t.Errorf("store accepted access mutation %d", i)
		}
	}
	gf := fl("198.51.100.23", FlowEstablished, "net-flows", "netflow")
	badF := []func(*FlowRecord){
		func(f *FlowRecord) { f.FlowID = "" },
		func(f *FlowRecord) { f.SrcIP = netip.MustParseAddr("::1") },
		func(f *FlowRecord) { f.State = "fin" },
	}
	for i, m := range badF {
		f := gf
		m(&f)
		if f.Validate() == nil {
			t.Errorf("flow mutation %d accepted", i)
		}
		if _, err := NewStore(baseReg(), nil, []FlowRecord{f}); err == nil {
			t.Errorf("store accepted flow mutation %d", i)
		}
	}
}

func TestVerdictText(t *testing.T) {
	for _, v := range []EvidenceVerdict{EvAbsent, EvInsufficient, EvCorroborated, EvConflict, 9} {
		b, _ := v.MarshalText()
		if string(b) != v.String() {
			t.Error("text")
		}
	}
	if EvidenceVerdict(9).String() != "invalid" {
		t.Error("invalid")
	}
}
