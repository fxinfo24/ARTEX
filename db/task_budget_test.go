package db

import "testing"

// TestTaskBudgetPersists: the per-task cap recorded at creation must come back on
// the task row, and a task created without one must report 0/0 so the engine
// inherits the process-wide setting instead of inventing a limit.
func TestTaskBudgetPersists(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		SkipPGUnavailable(t, err)
	}
	t.Cleanup(func() { _ = d.Close() })

	capped, err := d.CreateTaskWithOptions("budget", "goal", TaskCreateOptions{BudgetTokens: 250_000, BudgetTurns: 40})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cleanupErr(t, "task", d.DeleteTask(capped.ID)) })
	// The struct CreateTaskWithOptions returns is served back to the caller directly,
	// so it must carry the budget too — not just the row the INSERT wrote.
	if capped.BudgetTokens != 250_000 || capped.BudgetTurns != 40 {
		t.Fatalf("returned task budget = %d/%d, want 250000/40", capped.BudgetTokens, capped.BudgetTurns)
	}
	got, err := d.GetTask(capped.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.BudgetTokens != 250_000 || got.BudgetTurns != 40 {
		t.Fatalf("budget = %d/%d, want 250000/40", got.BudgetTokens, got.BudgetTurns)
	}

	plain, err := d.CreateTaskWithOptions("no budget", "goal", TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cleanupErr(t, "task", d.DeleteTask(plain.ID)) })
	got, err = d.GetTask(plain.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.BudgetTokens != 0 || got.BudgetTurns != 0 {
		t.Fatalf("default budget = %d/%d, want 0/0 (inherit)", got.BudgetTokens, got.BudgetTurns)
	}
}
