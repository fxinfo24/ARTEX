package agent

import "testing"

// TestBudgetsFromEnvForTask: a per-task value wins, 0 inherits the process-wide
// setting, and the two dimensions are independent — the behaviour the task-create
// fields rely on.
func TestBudgetsFromEnvForTask(t *testing.T) {
	t.Setenv("ARTEX_TASK_BUDGET_TOKENS", "1000")
	t.Setenv("ARTEX_TASK_BUDGET_TURNS", "10")
	t.Setenv("ARTEX_INTENT_BUDGET_TOKENS", "100")
	t.Setenv("ARTEX_INTENT_BUDGET_TURNS", "")

	cases := []struct {
		name       string
		tokens     int64
		turns      int64
		wantTokens int64
		wantTurns  int64
	}{
		{"zero inherits the env", 0, 0, 1000, 10},
		{"both overridden", 250, 3, 250, 3},
		{"tokens only", 250, 0, 250, 10},
		{"turns only", 0, 4, 1000, 4},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			task, intent := BudgetsFromEnvForTask(tc.tokens, tc.turns)
			if task.Tokens != tc.wantTokens || task.Turns != tc.wantTurns {
				t.Fatalf("task budget = %d/%d, want %d/%d", task.Tokens, task.Turns, tc.wantTokens, tc.wantTurns)
			}
			if intent.Tokens != 100 || intent.Turns != Unlimited {
				t.Fatalf("intent budget = %d/%d, want 100/Unlimited (the env values untouched)", intent.Tokens, intent.Turns)
			}
		})
	}

	// With no env budget at all, a per-task value is what creates the cap.
	t.Setenv("ARTEX_TASK_BUDGET_TOKENS", "")
	t.Setenv("ARTEX_TASK_BUDGET_TURNS", "")
	task, _ := BudgetsFromEnvForTask(500, 0)
	if task.Tokens != 500 || task.Turns != Unlimited {
		t.Fatalf("unset env with a task cap: %d/%d, want 500/Unlimited", task.Tokens, task.Turns)
	}
}
