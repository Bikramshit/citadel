// Package evidence implements corroboration over trusted log and flow fields
// (rules E1 and E2). A log-derived indicator may be acted on only if trusted
// records show the address behaving as the attack signature says, confirmed
// by an independent flow sensor. Mentions in attacker-written fields count
// for nothing: those fields are stored but never parsed as records.
//
// Corroborated means only that the configured evidence conditions held. It
// does not establish malicious intent or that a block is correct.
package evidence

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"time"
)

// AccessRecord is one web access record. The trusted fields are written by
// our server and auth service; the attacker-written fields come from the
// client and are never used as evidence.
type AccessRecord struct {
	// Trusted fields.
	EventID       string     `json:"event_id" yaml:"event_id"`
	TS            time.Time  `json:"ts" yaml:"ts"`
	Host          string     `json:"host" yaml:"host"`
	ClientIP      netip.Addr `json:"client_ip" yaml:"client_ip"` // from the connection
	Status        int        `json:"status" yaml:"status"`
	AuthResult    string     `json:"auth_result" yaml:"auth_result"`       // "fail", "success", or ""
	AuthPrincipal string     `json:"auth_principal" yaml:"auth_principal"` // set by the auth service, only on success
	SensorID      string     `json:"sensor_id" yaml:"sensor_id"`
	PipelineID    string     `json:"pipeline_id" yaml:"pipeline_id"`

	// Attacker-written fields.
	Path          string `json:"path" yaml:"path"`
	UserAgent     string `json:"user_agent" yaml:"user_agent"`
	XForwardedFor string `json:"x_forwarded_for" yaml:"x_forwarded_for"`
	AttemptedUser string `json:"attempted_user" yaml:"attempted_user"`
}

// FlowRecord is one network flow record, written by network equipment. It
// has no attacker-written fields.
type FlowRecord struct {
	FlowID     string     `json:"flow_id" yaml:"flow_id"`
	TS         time.Time  `json:"ts" yaml:"ts"`
	SrcIP      netip.Addr `json:"src_ip" yaml:"src_ip"`
	DstHost    string     `json:"dst_host" yaml:"dst_host"`
	State      string     `json:"state" yaml:"state"` // "established" or "syn_only"
	SensorID   string     `json:"sensor_id" yaml:"sensor_id"`
	PipelineID string     `json:"pipeline_id" yaml:"pipeline_id"`
}

// Flow states.
const (
	FlowEstablished = "established"
	FlowSynOnly     = "syn_only"
)

// Sensor is one registered log or flow sensor.
type Sensor struct {
	ID          string `json:"id" yaml:"id"`
	Kind        string `json:"kind" yaml:"kind"` // "access" or "flow"
	Pipeline    string `json:"pipeline" yaml:"pipeline"`
	DerivedFrom string `json:"derived_from" yaml:"derived_from"` // a sensor whose records this one is reconstructed from
}

// Registry is the inventory's view that evidence needs: shared addresses and
// the sensor registry that says which sensors and pipelines are distinct.
type Registry interface {
	IsPartnerOrShared(a netip.Addr) bool
	Sensors() []Sensor
}

// Validate checks a record's trusted fields.
func (r AccessRecord) Validate() error {
	switch {
	case r.EventID == "" || r.Host == "" || r.SensorID == "" || r.PipelineID == "":
		return fmt.Errorf("access record %q: missing trusted field", r.EventID)
	case !r.ClientIP.Is4() || r.ClientIP.Zone() != "":
		return fmt.Errorf("access record %q: client_ip must be IPv4", r.EventID)
	case r.TS.IsZero():
		return fmt.Errorf("access record %q: missing ts", r.EventID)
	case r.AuthResult != "" && r.AuthResult != "fail" && r.AuthResult != "success":
		return fmt.Errorf("access record %q: auth_result %q", r.EventID, r.AuthResult)
	case r.AuthPrincipal != "" && r.AuthResult != "success":
		return fmt.Errorf("access record %q: auth_principal is set only on success", r.EventID)
	}
	return nil
}

// Validate checks a flow record.
func (f FlowRecord) Validate() error {
	switch {
	case f.FlowID == "" || f.DstHost == "" || f.SensorID == "" || f.PipelineID == "" || f.TS.IsZero():
		return fmt.Errorf("flow record %q: missing field", f.FlowID)
	case !f.SrcIP.Is4() || f.SrcIP.Zone() != "":
		return fmt.Errorf("flow record %q: src_ip must be IPv4", f.FlowID)
	case f.State != FlowEstablished && f.State != FlowSynOnly:
		return fmt.Errorf("flow record %q: state %q", f.FlowID, f.State)
	}
	return nil
}

func writeLP(h interface{ Write([]byte) (int, error) }, s string) {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(s)))
	h.Write(n[:])
	h.Write([]byte(s))
}

// TrustedDigest is a digest of the record's trusted fields other than the
// event ID, with the timestamp truncated to the second. Records the pipeline
// delivered twice share it. Sensor and pipeline IDs are left out so a record
// delivered through two pipelines also collapses.
func (r AccessRecord) TrustedDigest() [32]byte {
	h := sha256.New()
	writeLP(h, "citadel-evidence-v1")
	writeLP(h, r.TS.UTC().Truncate(time.Second).Format(time.RFC3339))
	writeLP(h, r.Host)
	writeLP(h, r.ClientIP.String())
	writeLP(h, strconv.Itoa(r.Status))
	writeLP(h, r.AuthResult)
	writeLP(h, r.AuthPrincipal)
	var d [32]byte
	copy(d[:], h.Sum(nil))
	return d
}

// TaskScope is the run's evidence scope: hosts, window, and attack signature.
type TaskScope struct {
	Hosts     []string
	From, To  time.Time // the window, inclusive at both ends
	LoginPath string    // the login path for the 401/403 signature
}

// InWindow reports whether ts falls inside the task's window.
func (sc TaskScope) InWindow(ts time.Time) bool { return !ts.Before(sc.From) && !ts.After(sc.To) }

func (sc TaskScope) hasHost(h string) bool { return slices.Contains(sc.Hosts, h) }

// MatchesSignature reports whether an access record matches the task's
// brute-force signature: a failed authentication, or status 401 or 403 on
// the login path.
func (sc TaskScope) MatchesSignature(r AccessRecord) bool {
	if r.AuthResult == "fail" {
		return true
	}
	return (r.Status == 401 || r.Status == 403) && r.Path == sc.LoginPath
}

// EvidenceVerdict is the outcome of corroboration.
type EvidenceVerdict uint8

// Verdicts.
const (
	EvAbsent EvidenceVerdict = iota
	EvInsufficient
	EvCorroborated
	EvConflict
)

// String names the verdict.
func (v EvidenceVerdict) String() string {
	switch v {
	case EvAbsent:
		return "absent"
	case EvInsufficient:
		return "insufficient"
	case EvCorroborated:
		return "corroborated"
	case EvConflict:
		return "conflict"
	}
	return "invalid"
}

// MarshalText writes the verdict's name.
func (v EvidenceVerdict) MarshalText() ([]byte, error) { return []byte(v.String()), nil }

// UnmarshalText parses a verdict name, for replaying event logs.
func (v *EvidenceVerdict) UnmarshalText(b []byte) error {
	for _, c := range []EvidenceVerdict{EvAbsent, EvInsufficient, EvCorroborated, EvConflict} {
		if c.String() == string(b) {
			*v = c
			return nil
		}
	}
	return fmt.Errorf("unknown evidence verdict %q", string(b))
}

// Thresholds are the tuned evidence parameters, frozen in thresholds.yaml.
type Thresholds struct {
	K        int // observations required
	MinFlows int // established independent flows required (the flow requirement)
}

// Counts is the evidence shown on decision events and approval cards.
type Counts struct {
	Verdict       EvidenceVerdict `json:"verdict"`
	Observations  int             `json:"observations"`
	Flows         int             `json:"flows"`          // established flows from independent sensors
	SuccessLogins int             `json:"success_logins"` // accounts only
	Sensors       []string        `json:"sensors"`        // sensors whose records counted
	Conflict      string          `json:"conflict,omitempty"`
	K             int             `json:"k"`
	MinFlows      int             `json:"min_flows"`
}

// Conflict reasons.
const (
	ConflictShared  = "partner_or_shared_address"
	ConflictSensors = "independent_sensor_saw_no_traffic_from_address"
)

// Store holds the mock log store and flow records over which evidence is
// computed. It is read-only after construction.
type Store struct {
	reg    Registry
	access []AccessRecord
	flows  []FlowRecord
}

// NewStore validates and copies the records.
func NewStore(reg Registry, access []AccessRecord, flows []FlowRecord) (*Store, error) {
	for _, r := range access {
		if err := r.Validate(); err != nil {
			return nil, err
		}
	}
	for _, f := range flows {
		if err := f.Validate(); err != nil {
			return nil, err
		}
	}
	return &Store{reg: reg, access: slices.Clone(access), flows: slices.Clone(flows)}, nil
}

// Access returns the access records for hosts inside the window. Callers use
// only their trusted fields.
func (s *Store) Access(sc TaskScope) []AccessRecord {
	var out []AccessRecord
	for _, r := range s.access {
		if sc.hasHost(r.Host) && sc.InWindow(r.TS) {
			out = append(out, r)
		}
	}
	return out
}

// AllAccess returns a copy of every access record, for logs.read.
func (s *Store) AllAccess() []AccessRecord { return slices.Clone(s.access) }

// AllFlows returns a copy of every flow record.
func (s *Store) AllFlows() []FlowRecord { return slices.Clone(s.flows) }

// Independence is the set of flow sensors that count as independent of the
// access records.
type Independence struct {
	sensors map[string]string // flow sensor ID -> its registered pipeline
}

// IndependentOf returns the flow sensors independent of the given kind
// ("access"): registered flow sensors whose ID and pipeline are not shared
// with any access sensor or any access record in scope, and which are not
// reconstructed from an access sensor.
func (s *Store) IndependentOf(kind string, sc TaskScope) Independence {
	sensors := s.reg.Sensors()
	shared := map[string]bool{}
	sharedPipes := map[string]bool{}
	for _, x := range sensors {
		if x.Kind == kind {
			shared[x.ID], sharedPipes[x.Pipeline] = true, true
		}
	}
	for _, r := range s.Access(sc) {
		shared[r.SensorID], sharedPipes[r.PipelineID] = true, true
	}
	ind := Independence{sensors: map[string]string{}}
	for _, x := range sensors {
		if x.Kind != "flow" || shared[x.ID] || sharedPipes[x.Pipeline] || shared[x.DerivedFrom] {
			continue
		}
		ind.sensors[x.ID] = x.Pipeline
	}
	return ind
}

func (ind Independence) counts(f FlowRecord) bool {
	p, ok := ind.sensors[f.SensorID]
	return ok && p == f.PipelineID
}

func (s *Store) flowsInScope(sc TaskScope, ind Independence) []FlowRecord {
	var out []FlowRecord
	for _, f := range s.flows {
		if sc.hasHost(f.DstHost) && sc.InWindow(f.TS) && ind.counts(f) {
			out = append(out, f)
		}
	}
	return out
}

// SensorActive reports whether an independent flow sensor reported any
// traffic to the task's hosts in the window.
func (s *Store) SensorActive(sc TaskScope, ind Independence) bool {
	return len(s.flowsInScope(sc, ind)) > 0
}

// AnyFlows counts flows of any state from x to the task's hosts from
// independent sensors.
func (s *Store) AnyFlows(x netip.Addr, sc TaskScope, ind Independence) int {
	n := 0
	for _, f := range s.flowsInScope(sc, ind) {
		if f.SrcIP == x {
			n++
		}
	}
	return n
}

// EstablishedFlows counts established flows from x to the task's hosts from
// independent sensors. Spoofed SYN packets never reach established.
func (s *Store) EstablishedFlows(x netip.Addr, sc TaskScope, ind Independence) (int, []string) {
	n := 0
	var sensors []string
	for _, f := range s.flowsInScope(sc, ind) {
		if f.SrcIP == x && f.State == FlowEstablished {
			n++
			if !slices.Contains(sensors, f.SensorID) {
				sensors = append(sensors, f.SensorID)
			}
		}
	}
	return n, sensors
}

// observations counts deduplicated signature matches for x and returns the
// sensors that wrote them.
func (s *Store) observations(x netip.Addr, sc TaskScope) (int, []string) {
	seenID := map[string]bool{}
	seenDigest := map[[32]byte]bool{}
	obs := 0
	var sensors []string
	for _, r := range s.Access(sc) { // trusted fields only
		if r.ClientIP.Unmap() != x || !sc.MatchesSignature(r) {
			continue
		}
		d := r.TrustedDigest() // ts truncated to the second
		if seenID[r.EventID] || seenDigest[d] {
			continue
		}
		seenID[r.EventID], seenDigest[d] = true, true
		obs++
		if !slices.Contains(sensors, r.SensorID) {
			sensors = append(sensors, r.SensorID)
		}
	}
	return obs, sensors
}

// CorroborateIP decides the evidence verdict for an untrusted IP target,
// after authorization has already removed protected and internal addresses.
// Conditions are checked in the specification's order.
func (s *Store) CorroborateIP(x netip.Addr, sc TaskScope, th Thresholds) (EvidenceVerdict, Counts) {
	c := Counts{K: th.K, MinFlows: th.MinFlows}
	if s.reg.IsPartnerOrShared(x) {
		c.Verdict, c.Conflict = EvConflict, ConflictShared
		return EvConflict, c
	}
	obs, accessSensors := s.observations(x, sc)
	c.Observations = obs
	ind := s.IndependentOf("access", sc)
	if obs >= th.K && s.SensorActive(sc, ind) && s.AnyFlows(x, sc, ind) == 0 {
		c.Verdict, c.Conflict, c.Sensors = EvConflict, ConflictSensors, sortedUnion(accessSensors, nil)
		return EvConflict, c // independent sensors disagree
	}
	flows, flowSensors := s.EstablishedFlows(x, sc, ind)
	c.Flows = flows
	c.Sensors = sortedUnion(accessSensors, flowSensors)
	switch {
	case obs == 0:
		c.Verdict = EvAbsent
	case obs >= th.K && flows >= max(th.MinFlows, 1):
		c.Verdict = EvCorroborated
	default:
		c.Verdict = EvInsufficient
	}
	return c.Verdict, c
}

// CorroborateAccount decides the evidence verdict for an untrusted account
// target. Only access records with auth_result = success whose
// auth_principal is the account count, inside the task's hosts and window;
// attempted_user is attacker-chosen and never counts. Absent means no such
// login; Corroborated means one came from an IP that is itself corroborated;
// Insufficient means logins exist but none from a corroborated IP.
func (s *Store) CorroborateAccount(account string, sc TaskScope, th Thresholds) (EvidenceVerdict, Counts) {
	c := Counts{K: th.K, MinFlows: th.MinFlows}
	var ips []netip.Addr
	for _, r := range s.Access(sc) {
		if r.AuthResult == "success" && r.AuthPrincipal == account {
			c.SuccessLogins++
			if !slices.Contains(ips, r.ClientIP) {
				ips = append(ips, r.ClientIP)
			}
			if !slices.Contains(c.Sensors, r.SensorID) {
				c.Sensors = append(c.Sensors, r.SensorID)
			}
		}
	}
	slices.Sort(c.Sensors)
	if c.SuccessLogins == 0 {
		c.Verdict = EvAbsent
		return EvAbsent, c
	}
	c.Verdict = EvInsufficient
	slices.SortFunc(ips, func(a, b netip.Addr) int { return a.Compare(b) })
	for _, ip := range ips {
		if v, ic := s.CorroborateIP(ip, sc, th); v == EvCorroborated {
			c.Verdict = EvCorroborated
			c.Observations, c.Flows = ic.Observations, ic.Flows
			break
		}
	}
	return c.Verdict, c
}

func sortedUnion(a, b []string) []string {
	out := slices.Clone(a)
	for _, x := range b {
		if !slices.Contains(out, x) {
			out = append(out, x)
		}
	}
	slices.Sort(out)
	return out
}
