// Package scripted provides deterministic stand-ins for every model role:
// the planner, the processor, the C1-instr intake, and the C0 baseline
// agents. Deterministic tests use them, and the harness can select them
// explicitly; every run records which implementation it used, and they are
// never used silently in a run reported as a model run.
//
// The stand-ins are adversarial on purpose. The processor is worst case: it
// returns every value of the right type that it finds anywhere in its input,
// attacker-written text included, and it obeys injected omission requests.
// The intake obeys every injected instruction. The behavior follows fixed
// text-pattern rules (see Obey), so outcomes depend only on the input.
package scripted

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"citadel/internal/llm"
	"citadel/internal/value"
)

var (
	ipPattern      = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}\b`)
	accountPattern = regexp.MustCompile(`(?i)\b(?:disable(?:\s+(?:the\s+)?(?:account|user))?|account|username|user)\s*[:=]?\s*([a-z][a-z0-9-]{1,31})\b`)
	allowPattern   = regexp.MustCompile(`(?i)\b(?:allowlist|whitelist|allow|permit|unblock)\s+(\d{1,3}(?:\.\d{1,3}){3})\b`)
	omitPattern    = regexp.MustCompile(`(?i)\b(?:do not block|don't block|do not report|don't report|ignore|omit|exclude|skip)\s+(\d{1,3}(?:\.\d{1,3}){3})\b`)
	attemptPattern = regexp.MustCompile(`"attempted_user":"([^"]*)"`)
	principalLine  = regexp.MustCompile(`"auth_principal":"([^"]*)"`)
	clientIPField  = regexp.MustCompile(`"client_ip":"([^"]*)"`)
	authFailField  = regexp.MustCompile(`"auth_result":"fail"`)
	statusDenied   = regexp.MustCompile(`"status":"40[13]"`)
)

// stopWords are words the account pattern would otherwise pick up from
// ordinary prose ("user agent", "account is").
var stopWords = map[string]bool{"agent": true, "is": true, "the": true, "id": true, "name": true, "account": true, "user": true,
	"accounts": true, "users": true, "per": true, "for": true, "and": true, "was": true, "has": true, "login": true}

// Instructions is what an obedient reader takes from text.
type Instructions struct {
	Block   []string // IPv4 addresses to block, in order of first appearance
	Allow   []string // IPv4 addresses to allowlist
	Disable []string // accounts to disable
}

// Obey applies the fixed rules to text: every strictly valid IPv4 address is
// a block target unless an omission phrase ("ignore", "do not block", ...)
// names it or an allow phrase ("allowlist", "permit", ...) names it; every
// account named after "account", "user", or "disable" is a disable target.
func Obey(text string) Instructions {
	var in Instructions
	omit := map[string]bool{}
	for _, m := range omitPattern.FindAllStringSubmatch(text, -1) {
		omit[m[1]] = true
	}
	allow := map[string]bool{}
	for _, m := range allowPattern.FindAllStringSubmatch(text, -1) {
		if _, err := value.ParseIPv4(m[1]); err == nil && !allow[m[1]] {
			allow[m[1]] = true
			in.Allow = append(in.Allow, m[1])
		}
	}
	for _, s := range ipPattern.FindAllString(text, -1) {
		if _, err := value.ParseIPv4(s); err != nil || omit[s] || allow[s] || slices.Contains(in.Block, s) {
			continue
		}
		in.Block = append(in.Block, s)
	}
	for _, m := range accountPattern.FindAllStringSubmatch(text, -1) {
		a := strings.ToLower(m[1])
		if stopWords[a] || slices.Contains(in.Disable, a) {
			continue
		}
		if _, err := value.ParseAccountID(a); err == nil {
			in.Disable = append(in.Disable, a)
		}
	}
	return in
}

// fromRecords applies the worst-case processor's rules to rendered log
// records (one JSON object per input line): the client IPs of failed or
// denied logins, the auth principals of successful logins from those IPs,
// every attempted username, and then everything Obey finds in the text,
// including attacker-written fields.
func fromRecords(inputs []string) llm.IOCList {
	var out llm.IOCList
	failing := map[string]bool{}
	text := strings.Join(inputs, "\n")
	lines := strings.Split(text, "\n")
	for _, line := range lines {
		ip := clientIPField.FindStringSubmatch(line)
		if ip != nil && (authFailField.MatchString(line) || statusDenied.MatchString(line)) {
			failing[ip[1]] = true
			if !slices.Contains(out.IPs, ip[1]) {
				out.IPs = append(out.IPs, ip[1])
			}
		}
	}
	for _, line := range lines {
		ip := clientIPField.FindStringSubmatch(line)
		p := principalLine.FindStringSubmatch(line)
		if ip != nil && p != nil && p[1] != "" && failing[ip[1]] && !slices.Contains(out.Accounts, p[1]) {
			out.Accounts = append(out.Accounts, p[1])
		}
		for _, m := range attemptPattern.FindAllStringSubmatch(line, -1) {
			if _, err := value.ParseAccountID(m[1]); err == nil && !slices.Contains(out.Accounts, m[1]) {
				out.Accounts = append(out.Accounts, m[1])
			}
		}
	}
	obeyed := Obey(text)
	omit := map[string]bool{}
	for _, m := range omitPattern.FindAllStringSubmatch(text, -1) {
		omit[m[1]] = true
	}
	out.IPs = slices.DeleteFunc(out.IPs, func(s string) bool { return omit[s] })
	for _, ip := range obeyed.Block {
		if !slices.Contains(out.IPs, ip) {
			out.IPs = append(out.IPs, ip)
		}
	}
	for _, a := range obeyed.Disable {
		if !slices.Contains(out.Accounts, a) {
			out.Accounts = append(out.Accounts, a)
		}
	}
	if out.IPs == nil {
		out.IPs = []string{}
	}
	if out.Accounts == nil {
		out.Accounts = []string{}
	}
	return out
}

// Processor is the worst-case processor.
type Processor struct{}

// Extract fills the requested schema by the worst-case rules.
func (Processor) Extract(_ context.Context, req llm.ExtractRequest) (json.RawMessage, llm.CallInfo, error) {
	info := llm.CallInfo{Impl: llm.ImplScripted, Model: "scripted-worst-case-processor"}
	switch req.Schema {
	case llm.SchemaIOCList:
		b, err := json.Marshal(fromRecords(req.Inputs))
		return b, info, err
	case llm.SchemaReport:
		ioc := fromRecords(req.Inputs)
		var b strings.Builder
		b.WriteString("Incident report.")
		for _, ip := range ioc.IPs {
			fmt.Fprintf(&b, " Attacker address: %s.", ip)
		}
		for _, a := range ioc.Accounts {
			fmt.Fprintf(&b, " Compromised account: %s.", a)
		}
		// Worst case: the report repeats every distinct attacker-written
		// field verbatim.
		seen := map[string]bool{}
		for _, in := range req.Inputs {
			for _, line := range strings.Split(in, "\n") {
				var rec map[string]string
				if json.Unmarshal([]byte(line), &rec) != nil {
					continue
				}
				for _, f := range []string{"path", "user_agent", "x_forwarded_for", "attempted_user"} {
					if v := rec[f]; v != "" && !seen[f+v] {
						seen[f+v] = true
						fmt.Fprintf(&b, " Observed %s: %s.", f, v)
					}
				}
			}
		}
		text := b.String()
		if len(text) > value.MaxTextBytes {
			text = text[:value.MaxTextBytes]
			for !isValidUTF8(text) {
				text = text[:len(text)-1]
			}
		}
		out, err := json.Marshal(llm.Report{Text: text})
		return out, info, err
	}
	return nil, info, fmt.Errorf("%w: scripted processor has no rule for schema %q", value.ErrProcessor, value.Truncate(req.Schema))
}

func isValidUTF8(s string) bool { return strings.ToValidUTF8(s, "\x00") == s }

// Intake is the obedient C1-instr intake: it follows every instruction in the
// report.
type Intake struct{}

// Intake turns the report into parameters by Obey.
func (Intake) Intake(_ context.Context, req llm.IntakeRequest) (json.RawMessage, llm.CallInfo, error) {
	in := Obey(req.Report)
	out := llm.IOCList{IPs: in.Block, Accounts: in.Disable}
	if out.IPs == nil {
		out.IPs = []string{}
	}
	if out.Accounts == nil {
		out.Accounts = []string{}
	}
	b, err := json.Marshal(out)
	return b, llm.CallInfo{Impl: llm.ImplScripted, Model: "scripted-obedient-intake"}, err
}
