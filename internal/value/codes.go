package value

import "errors"

// Code is a specification error code such as "ERR_BAD_SIG". A Code is itself
// an error, so each code has exactly one sentinel value below; callers wrap it
// with fmt.Errorf("%w: ...") and check it with errors.Is.
//
// The codes live here because every component that rejects input imports
// this package, and the specification's package list has no separate errors
// package.
type Code string

// Error returns the code.
func (c Code) Error() string { return string(c) }

// CodeOf returns the specification code carried by err, or "" if none.
func CodeOf(err error) string {
	var c Code
	if errors.As(err, &c) {
		return string(c)
	}
	return ""
}

// Error codes named by the specification (receiver steps, interpreter).
const (
	ErrSize            Code = "ERR_SIZE"
	ErrSchema          Code = "ERR_SCHEMA"
	ErrUnknownKey      Code = "ERR_UNKNOWN_KEY"
	ErrBadSig          Code = "ERR_BAD_SIG"
	ErrSender          Code = "ERR_SENDER"
	ErrRecipient       Code = "ERR_RECIPIENT"
	ErrExpired         Code = "ERR_EXPIRED"
	ErrTTL             Code = "ERR_TTL"
	ErrPreStart        Code = "ERR_PRE_START"
	ErrReplay          Code = "ERR_REPLAY"
	ErrInProgress      Code = "ERR_IN_PROGRESS"
	ErrAuthCtx         Code = "ERR_AUTHCTX"
	ErrNotParticipant  Code = "ERR_NOT_PARTICIPANT"
	ErrContextConflict Code = "ERR_CONTEXT_CONFLICT"
	ErrRunClosed       Code = "ERR_RUN_CLOSED"
	ErrWorkflow        Code = "ERR_WORKFLOW"
	ErrUnknownTask     Code = "ERR_UNKNOWN_TASK"
	ErrExcessGrant     Code = "ERR_EXCESS_GRANT"
	ErrType            Code = "ERR_TYPE"
	ErrUntrustedBranch Code = "ERR_UNTRUSTED_BRANCH"
)

// Codes for conditions the specification names without an ERR_ code (the
// pseudocode's ErrNoHandoffCap, ErrUntrustedPC, and approval errors) or
// describes without naming. Each is listed in docs/TRACEABILITY.md.
const (
	ErrNoHandoffCap     Code = "ERR_NO_HANDOFF_CAP"    // H1, sender side
	ErrUntrustedPC      Code = "ERR_UNTRUSTED_PC"      // H3, sender side
	ErrNoSuchApproval   Code = "ERR_NO_SUCH_APPROVAL"  // Approve on an unknown key
	ErrNotPrincipal     Code = "ERR_NOT_PRINCIPAL"     // approver is not the context's principal
	ErrApprovalExpired  Code = "ERR_APPROVAL_EXPIRED"  // approval past its expiry
	ErrApprovalClosed   Code = "ERR_APPROVAL_CLOSED"   // approval already used, rejected, or expired
	ErrIterationBudget  Code = "ERR_ITERATION_BUDGET"  // loop longer than the iteration budget
	ErrPlanRejected     Code = "ERR_PLAN_REJECTED"     // static check failed
	ErrPlanInvalid      Code = "ERR_PLAN_INVALID"      // planner output invalid after retries
	ErrDecode           Code = "ERR_DECODE"            // processor output failed strict decoding
	ErrProcessor        Code = "ERR_PROCESSOR"         // processor error or not enough information
	ErrToolFailed       Code = "ERR_TOOL_FAILED"       // definite tool rejection
	ErrToolUncertain    Code = "ERR_TOOL_UNCERTAIN"    // tool outcome unknown after reconciliation
	ErrUndefinedValue   Code = "ERR_UNDEFINED_VALUE"   // reference to a value whose call was denied
	ErrNotAdmitted      Code = "ERR_NOT_ADMITTED"      // tool given an attempt that Admit did not issue
	ErrKeyPermissions   Code = "ERR_KEY_PERMISSIONS"   // private key file readable by group or others
	ErrConfig           Code = "ERR_CONFIG"            // missing or invalid configuration
	ErrApprovalDeclined Code = "ERR_APPROVAL_DECLINED" // escalation declined or timed out: a Deny
	ErrModel            Code = "ERR_MODEL"             // model call failed after allowed retries
)
