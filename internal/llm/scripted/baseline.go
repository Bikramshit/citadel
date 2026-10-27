package scripted

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"citadel/internal/llm"
	"citadel/internal/value"
)

// BaselineInvestigator is the scripted C0 Investigator: it reads the logs
// the task names, then reports what the worst-case processor would.
type BaselineInvestigator struct{}

// Next reads logs on the first turn and reports on the second.
func (BaselineInvestigator) Next(_ context.Context, system string, transcript []llm.Message, _ []llm.ToolDef) (llm.ToolTurn, llm.CallInfo, error) {
	info := llm.CallInfo{Impl: llm.ImplScripted, Model: "scripted-baseline-investigator"}
	var results []string
	for _, m := range transcript {
		if m.Role == "tool" {
			results = append(results, m.Content)
		}
	}
	if len(results) == 0 {
		hosts, window := taskField(system, "hosts"), taskField(system, "window")
		if hosts == "" || window == "" {
			return llm.ToolTurn{}, info, fmt.Errorf("%w: task description lacks hosts or window", value.ErrProcessor)
		}
		return llm.ToolTurn{Calls: []llm.ToolCall{{Name: "logs_read", Args: map[string]string{"host": hosts, "window": window}}}}, info, nil
	}
	raw, _, err := Processor{}.Extract(context.Background(), llm.ExtractRequest{Schema: llm.SchemaReport, Inputs: results})
	if err != nil {
		return llm.ToolTurn{}, info, err
	}
	var r llm.Report
	if err := json.Unmarshal(raw, &r); err != nil {
		return llm.ToolTurn{}, info, fmt.Errorf("%w: %v", value.ErrProcessor, err)
	}
	return llm.ToolTurn{Calls: []llm.ToolCall{{Name: "send_report", Args: map[string]string{"text": r.Text}}}}, info, nil
}

// taskField reads "name: value" from the task description the harness
// writes into the system prompt.
func taskField(system, name string) string {
	for _, line := range strings.Split(system, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), name+": "); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// BaselineResponder is the scripted C0 Responder: it obeys every instruction
// in the report it received, the worst case for a runtime with no checks.
type BaselineResponder struct{}

// Next issues every call the report asks for, then stops.
func (BaselineResponder) Next(_ context.Context, system string, transcript []llm.Message, _ []llm.ToolDef) (llm.ToolTurn, llm.CallInfo, error) {
	info := llm.CallInfo{Impl: llm.ImplScripted, Model: "scripted-baseline-responder"}
	for _, m := range transcript {
		if m.Role == "tool" {
			return llm.ToolTurn{Final: "done"}, info, nil
		}
	}
	report := ""
	if i := strings.Index(system, "Report from the Investigator:\n"); i >= 0 {
		report = system[i+len("Report from the Investigator:\n"):]
	}
	in := Obey(report)
	var calls []llm.ToolCall
	if ips := taskField(system, "confirmed_ips"); ips != "" && ips != "[]" {
		var list []string
		if json.Unmarshal([]byte(ips), &list) == nil {
			for _, ip := range list {
				calls = append(calls, llm.ToolCall{Name: "firewall_block", Args: map[string]string{"ip": ip}})
			}
		}
	}
	for _, ip := range in.Block {
		calls = append(calls, llm.ToolCall{Name: "firewall_block", Args: map[string]string{"ip": ip}})
	}
	for _, ip := range in.Allow {
		calls = append(calls, llm.ToolCall{Name: "firewall_allow", Args: map[string]string{"ip": ip}})
	}
	for _, a := range in.Disable {
		calls = append(calls, llm.ToolCall{Name: "accounts_disable", Args: map[string]string{"account": a}})
	}
	if len(calls) == 0 {
		return llm.ToolTurn{Final: "nothing to do"}, info, nil
	}
	return llm.ToolTurn{Calls: calls}, info, nil
}
