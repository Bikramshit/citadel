# Traceability

Every rule ID, test ID, and invariant in [ARCHITECTURE.md](ARCHITECTURE.md) maps to the Go tests that check it. `TestTraceability` in `internal/harness/traceability_test.go` parses this file. It fails CI if a specification ID is missing, if a rule lacks a positive or a negative test, or if a listed test does not exist.

Test names are given in backticks; "Files" lists where they live. When one function covers both the positive and the negative case of a rule, it appears in both columns.

## Rules

| Rule | Positive tests | Negative tests | Files |
| --- | --- | --- | --- |
| A0 | `TestA0_ContextValid` | `TestA0_ContextValid`, `TestCT5_ExpiryBetweenDecideAndAdmit`, `TestAdmitPassesDenyAndChecksBinding`, `TestHandoffAllowance` | internal/policy/policy_test.go, internal/runstate/runstate_test.go |
| A1 | `TestA1_Capability`, `TestD1_FullWorkflowBenign` | `TestA1_Capability`, `TestTA1_InvestigatorFirewallCallRejected`, `TestTA2_ResponderAllowRejected`, `TestD3_DisableWithoutGrantRejected` | internal/policy/policy_test.go, internal/harness/enforcement_test.go |
| A2 | `TestA2_ResourceScope` | `TestA2_ResourceScope`, `TestTA3_TargetsOutsideScopeDenied` | internal/policy/policy_test.go, internal/harness/enforcement_test.go |
| A3 | `TestA3_Protected` | `TestA3_Protected`, `TestA3_ProtectedPublicAsset`, `TestET5_ProtectedInAttackerTextDeniedByA3`, `TestTA3_TargetsOutsideScopeDenied` | internal/policy/policy_test.go, internal/policy/evidence_cases_test.go, internal/harness/enforcement_test.go |
| A4 | `TestA4_Budgets` | `TestA4_Budgets`, `TestTA7_FiftyFirstBlockDenied`, `TestCT3_ConcurrentAdmitExactlyTheLimit` | internal/runstate/runstate_test.go, internal/harness/enforcement_test.go |
| A5 | `TestA5_DuplicateAttempt` | `TestA5_DuplicateAttempt`, `TestX1_LostResponseReconciledNotRepeated` | internal/runstate/runstate_test.go, internal/harness/enforcement_test.go |
| I1 | `TestI1_TaskOperation` | `TestI1_TaskOperation`, `TestTA5_WrongGrantStillDeniedByIntent`, `TestTA2_ResponderAllowRejected` | internal/policy/policy_test.go, internal/harness/enforcement_test.go |
| I2 | `TestI2_TargetAuthority` | `TestI2_TargetAuthority`, `TestTA4_LiteralTargetRejected`, `TestI2_InventoryTargetRejected` | internal/policy/policy_test.go, internal/harness/enforcement_test.go |
| I3 | `TestI3_ActionLiteral` | `TestI3_ActionLiteral`, `TestDecodeIsStrict`, `TestStaticCheckRejections` | internal/policy/policy_test.go, internal/plan/plan_test.go |
| F0 | `TestF0_ReadOnlyRoute` | `TestF0_ReadOnlyRoute` | internal/policy/policy_test.go |
| F1 | `TestF1_AnalystTarget` | `TestF1_AnalystTarget` | internal/policy/policy_test.go |
| F3 | `TestF3_UntrustedLoopVolume`, `TestTA7_FiftyFirstBlockDenied` | `TestF3_UntrustedLoopVolume` | internal/runstate/runstate_test.go, internal/harness/enforcement_test.go |
| E1 | `TestE1_IPEvidence`, `TestET1_CorroboratedAllows` | `TestE1_IPEvidence`, `TestET2_FabricatedIPInUserAgentAbsent`, `TestP4_FabricatedIndicatorDeniedByE1` | internal/policy/policy_test.go, internal/policy/evidence_cases_test.go, internal/harness/enforcement_test.go |
| E2 | `TestE2_AccountEvidence`, `TestET8_AccountEvidence` | `TestE2_AccountEvidence`, `TestET8_AccountEvidence` | internal/policy/policy_test.go, internal/policy/evidence_cases_test.go |
| H1 | `TestH1H2_SenderChecks`, `TestD1_FullWorkflowBenign` | `TestH1H2_SenderChecks`, `TestD5_UnlistedHandoffDenied` | internal/handoff/protocol_test.go, internal/harness/enforcement_test.go |
| H2 | `TestH1H2_SenderChecks` | `TestH1H2_SenderChecks`, `TestD2_RequestedAllowRefused`, `TestSenderRefusalsSendNothing` | internal/handoff/protocol_test.go, internal/handoff/sender_test.go, internal/harness/enforcement_test.go |
| H3 | `TestP13_SenderRefusesHandoffUnderUntrustedLoop` | `TestP13_SenderRefusesHandoffUnderUntrustedLoop`, `TestP13_HandoffInUntrustedLoopRejected` | internal/handoff/protocol_test.go, internal/harness/enforcement_test.go |
| H4 | `TestH4H5H6_ValidEnvelopeAccepted`, `TestP5_ReplayOfAcceptedEnvelope` | `TestP1_DataValueAltered`, `TestP5_ReplayOfAcceptedEnvelope`, `TestP6_Expired`, `TestP8_WrongRecipient`, `TestP9_UnknownKeyID` | internal/handoff/protocol_test.go |
| H5 | `TestH4H5H6_ValidEnvelopeAccepted`, `TestTA6_RequestedOpsExceedRunGrant` | `TestTA6_RequestedOpsExceedRunGrant`, `TestCT1_DuplicateEnvelopeAcceptedOnce`, `TestCT2_TwoEnvelopesOneRun`, `TestCT6_ClosedConflictingAndForeignContexts` | internal/handoff/protocol_test.go |
| H6 | `TestH4H5H6_ValidEnvelopeAccepted` | `TestP11_UnknownFieldDuplicateKeyWrongType`, `TestP15_SizeAndListLimits` | internal/handoff/protocol_test.go |
| C1 | `TestC1_Confidentiality` | `TestC1_Confidentiality` | internal/policy/policy_test.go |
| D0 | not applicable | `TestD0_Default` | internal/policy/policy_test.go |

## Tests

| ID | Tests | Files |
| --- | --- | --- |
| T-A1 | `TestTA1_InvestigatorFirewallCallRejected` | internal/harness/enforcement_test.go |
| T-A2 | `TestTA2_ResponderAllowRejected` | internal/harness/enforcement_test.go |
| T-A3 | `TestTA3_TargetsOutsideScopeDenied` | internal/harness/enforcement_test.go |
| T-A4 | `TestTA4_LiteralTargetRejected` | internal/harness/enforcement_test.go |
| T-A5 | `TestTA5_WrongGrantStillDeniedByIntent`, `TestI1_TaskOperation` | internal/harness/enforcement_test.go, internal/policy/policy_test.go |
| T-A6 | `TestTA6_RequestedOpsExceedRunGrant` | internal/handoff/protocol_test.go |
| T-A7 | `TestTA7_FiftyFirstBlockDenied` | internal/harness/enforcement_test.go |
| D1 | `TestD1_FullWorkflowBenign` | internal/harness/enforcement_test.go |
| D2 | `TestD2_RequestedAllowRefused`, `TestH1H2_SenderChecks` | internal/harness/enforcement_test.go, internal/handoff/protocol_test.go |
| D3 | `TestD3_DisableWithoutGrantRejected` | internal/harness/enforcement_test.go |
| D4 | `TestD4_TamperedRequestOrGrant` | internal/handoff/protocol_test.go |
| D5 | `TestD5_UnlistedHandoffDenied`, `TestH1H2_SenderChecks` | internal/harness/enforcement_test.go, internal/handoff/protocol_test.go |
| E-T1 | `TestET1_CorroboratedAllows` | internal/policy/evidence_cases_test.go |
| E-T2 | `TestET2_FabricatedIPInUserAgentAbsent` | internal/policy/evidence_cases_test.go |
| E-T3 | `TestET3_FiftyForgedLinesInOneHeaderAbsent` | internal/policy/evidence_cases_test.go |
| E-T4 | `TestET4_DuplicatedDeliveryInsufficient` | internal/policy/evidence_cases_test.go |
| E-T5 | `TestET5_ProtectedInAttackerTextDeniedByA3` | internal/policy/evidence_cases_test.go |
| E-T6 | `TestET6_PartnerAddressConflict` | internal/policy/evidence_cases_test.go |
| E-T7 | `TestET7_CorroboratedButNotPermitted` | internal/policy/evidence_cases_test.go |
| E-T8 | `TestET8_AccountEvidence` | internal/policy/evidence_cases_test.go |
| E-T9 | `TestET9_SynOnlyFlowsInsufficient` | internal/policy/evidence_cases_test.go |
| E-T10 | `TestET10_ListedSharedAddressConflict`, `TestET10_ApproverDeclinesSharedAddress` | internal/policy/evidence_cases_test.go, internal/harness/enforcement_test.go |
| E-T11 | `TestET11_UnlistedSharedAddressAllowed`, `TestET11_UnlistedSharedAddressBlocked` | internal/policy/evidence_cases_test.go, internal/harness/enforcement_test.go |
| E-T12 | `TestET12_CorrelatedEvidenceInsufficient` | internal/policy/evidence_cases_test.go |
| E-T13 | `TestET13_ConflictingSensors` | internal/policy/evidence_cases_test.go |
| P1 | `TestP1_DataValueAltered` | internal/handoff/protocol_test.go |
| P2 | `TestP2_ClaimedSourcesAltered` | internal/handoff/protocol_test.go |
| P3 | `TestP3_ResignedWithAnotherAgentsKey` | internal/handoff/protocol_test.go |
| P4 | `TestP4_CompromisedSenderStillUntrusted`, `TestP4_FabricatedIndicatorDeniedByE1` | internal/handoff/protocol_test.go, internal/harness/enforcement_test.go |
| P5 | `TestP5_ReplayOfAcceptedEnvelope` | internal/handoff/protocol_test.go |
| P6 | `TestP6_Expired` | internal/handoff/protocol_test.go |
| P7 | `TestP7_LifetimeOverFiveMinutes` | internal/handoff/protocol_test.go |
| P8 | `TestP8_WrongRecipient` | internal/handoff/protocol_test.go |
| P9 | `TestP9_UnknownKeyID` | internal/handoff/protocol_test.go |
| P10 | `TestP10_RevokedKey` | internal/handoff/protocol_test.go |
| P11 | `TestP11_UnknownFieldDuplicateKeyWrongType` | internal/handoff/protocol_test.go |
| P12 | `TestP12_RequestedFirewallAllow` | internal/handoff/protocol_test.go |
| P13 | `TestP13_SenderRefusesHandoffUnderUntrustedLoop`, `TestP13_HandoffInUntrustedLoopRejected` | internal/handoff/protocol_test.go, internal/harness/enforcement_test.go |
| P14 | `TestP14_MalformedOuter` | internal/handoff/protocol_test.go |
| P15 | `TestP15_SizeAndListLimits` | internal/handoff/protocol_test.go |
| P16 | `TestP16_IssuedBeforeReceiverStart` | internal/handoff/protocol_test.go |
| P17 | `TestP17_ContextSignedByNonOrchestrator` | internal/handoff/protocol_test.go |
| P18 | `TestP18_SecondHandoffWithFreshNonce` | internal/handoff/protocol_test.go |
| L1 | `TestL1_JoinProperties`, `TestL1_JoinReadersIntersect`, `TestL1_SourcesSortedDeduplicated` | internal/label/label_test.go |
| L2 | `TestL2_NoExportedFunctionRemovesSources`, `FuzzJoinNeverLosesSources` | internal/label/label_test.go |
| L3 | `TestL3_UntrustedBranchAborts` | internal/harness/enforcement_test.go |
| L4 | `TestL4_LongUntrustedLoopAbortsBeforeFirstIteration` | internal/harness/enforcement_test.go |
| L5 | `TestL5_ProcessorTrustedFieldRejected`, `TestDecodeOutputStrict` | internal/harness/enforcement_test.go, internal/llm/llm_test.go |
| L6 | `TestL6_RoundTripValuesUntrusted` | internal/handoff/protocol_test.go |
| L7 | `TestL7_ApprovalBoundToOneCall` | internal/runstate/runstate_test.go |
| CT1 | `TestCT1_DuplicateEnvelopeAcceptedOnce` | internal/handoff/protocol_test.go |
| CT2 | `TestCT2_TwoEnvelopesOneRun` | internal/handoff/protocol_test.go |
| CT3 | `TestCT3_ConcurrentAdmitExactlyTheLimit` | internal/runstate/runstate_test.go |
| CT4 | `TestCT4_ApprovalsAtomic` | internal/runstate/runstate_test.go |
| CT5 | `TestCT5_ExpiryBetweenDecideAndAdmit`, `TestCT5_ExpiredEmbeddedContext` | internal/runstate/runstate_test.go, internal/handoff/protocol_test.go |
| CT6 | `TestCT6_ClosedConflictingAndForeignContexts` | internal/handoff/protocol_test.go |
| CT7 | `TestCT7_RestartFailsClosed` | internal/handoff/protocol_test.go |
| X1 | `TestX1_LostResponseReconciledNotRepeated` | internal/harness/enforcement_test.go |
| X2 | `TestX2_UncertainOutcomeReportedHonestly` | internal/harness/enforcement_test.go |
| X3 | `TestX3_NeverReachedTheToolNoRetry` | internal/harness/enforcement_test.go |
| M1 | `TestM1` | internal/harness/m1_test.go |

## Invariants

`harness.CheckInvariants` (internal/harness/invariants.go) checks every invariant after every deterministic test that goes through `harness.Run` and after every harness run. `TestInvariantCheckerDetectsEachInvariant` shows it detects a violation of each one.

| Invariant | Statement (short) | Tests |
| --- | --- | --- |
| 1 | No state change outside the allowed set unless from an approved Escalate | `TestInvariantCheckerDetectsEachInvariant`, `TestB1toB12_ScriptedExpectedOutcomes`, `TestAttackFixturesScriptedDesignExpectations` |
| 2 | Every executed sensitive call has an A1 match and a route | `TestInvariantCheckerDetectsEachInvariant`, `TestD1_FullWorkflowBenign` |
| 3 | No event marks an untrusted value trusted | `TestInvariantCheckerDetectsEachInvariant`, `TestM1` |
| 4 | The Investigator never holds a firewall or account operation | `TestInvariantCheckerDetectsEachInvariant`, `TestD1_FullWorkflowBenign` |
| 5 | A rejected envelope produces no acceptance and no import | `TestInvariantCheckerDetectsEachInvariant`, `TestP1_DataValueAltered` |
| 6 | Each approval key is used at most once | `TestInvariantCheckerDetectsEachInvariant`, `TestCT4_ApprovalsAtomic`, `TestL7_ApprovalBoundToOneCall` |
| 7 | No executed call targets a protected resource | `TestInvariantCheckerDetectsEachInvariant`, `TestM1` |
| 8 | Every tool call has an attempt admitted by Admit | `TestInvariantCheckerDetectsEachInvariant`, `TestFirewallApplyIdempotentAndAdmittedOnly`, `TestOnePathToTool` |
| 9 | No idempotency key is applied more than once | `TestInvariantCheckerDetectsEachInvariant`, `TestX1_LostResponseReconciledNotRepeated` |
| 10 | Every change maps to a Succeeded or Uncertain attempt | `TestInvariantCheckerDetectsEachInvariant`, `TestX3_NeverReachedTheToolNoRetry` |
| 11 | No uncertain attempt is reported as denied or failed | `TestInvariantCheckerDetectsEachInvariant`, `TestX2_UncertainOutcomeReportedHonestly` |
| 12 | Allowances, budgets, and approvals never exceed their limits | `TestInvariantCheckerDetectsEachInvariant`, `TestCT1_DuplicateEnvelopeAcceptedOnce`, `TestCT3_ConcurrentAdmitExactlyTheLimit` |
| 13 | No state change belongs to a closed or pre-start run | `TestInvariantCheckerDetectsEachInvariant`, `TestCT7_RestartFailsClosed`, `TestP16_IssuedBeforeReceiverStart` |

## Fuzz targets

| Target | Covers | File |
| --- | --- | --- |
| `FuzzDecodeOuter` | Outer decoding | internal/handoff/sender_test.go |
| `FuzzDecodePayload` | Payload decoding with the duplicate-key pre-pass | internal/handoff/sender_test.go |
| `FuzzVerifyMutatedEnvelope` | Any changed byte of a valid envelope is rejected | internal/handoff/sender_test.go |
| `FuzzParseIPv4` | IPv4 parsing round-trips to the same canonical string | internal/value/value_test.go |
| `FuzzParseAccountID` | Account-ID parsing | internal/value/value_test.go |
| `FuzzParseHostname` | Host-name parsing | internal/value/value_test.go |
| `FuzzDecodeStrict` | Strict JSON decoding | internal/value/value_test.go |
| `FuzzApprovalKeyEncoding` | Approval-key encoding is decodable, so distinct inputs cannot collide | internal/policy/policy_test.go |
| `FuzzJoinNeverLosesSources` | L2 fuzzing | internal/label/label_test.go |

## Golden vectors

| Vector file | Test | Source of truth |
| --- | --- | --- |
| testdata/vectors/signed_envelopes.json | `TestSignedEnvelopeGoldenVectors` | An independent Ed25519 implementation (Python `cryptography`) |
| testdata/vectors/approval_keys.json | `TestApprovalKeyGoldenVectors` | An independent implementation of the documented encoding (Python `hashlib`) |
| testdata/vectors/idempotency_keys.json | `TestIdemKeyGoldenVectors` | An independent implementation of the documented encoding (Python `hashlib`) |
