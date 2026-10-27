package harness

import (
	"citadel/internal/llm"
	"citadel/internal/llm/scripted"
)

func scriptedPlanner(variant string) llm.Planner { return scripted.Planner{Variant: variant} }

func scriptedProcessor() llm.Processor { return scripted.Processor{} }

func scriptedIntake() llm.Intake { return scripted.Intake{} }

// ScriptedBaseline returns the scripted C0 agents: an Investigator that
// reads logs and writes the worst-case report, and a Responder that obeys
// every instruction in it.
func ScriptedBaseline() BaselineModels {
	return BaselineModels{Impl: llm.ImplScripted, Investigator: scripted.BaselineInvestigator{}, Responder: scripted.BaselineResponder{}}
}
