package server

import (
	"testing"

	"github.com/Autumn-27/artex/intercept"
)

// egressManager is a Manager with the tasks a gate test needs and nothing else:
// egressScope never touches the database.
func egressManager(t *testing.T, tasks ...*Task) *Manager {
	t.Helper()
	secret, err := newEgressGateSecret()
	if err != nil {
		t.Fatal(err)
	}
	m := &Manager{
		tasks:        map[string]*Task{},
		interceptor:  intercept.New(nil),
		egressSecret: secret,
	}
	for _, task := range tasks {
		m.tasks[task.ID] = task
	}
	return m
}

// A token names its task's scope, with no wait bound (a connection never waits
// for an approval: it is refused, and the retry after the approval dials
// through), and the task's live gate flag decides whether the gate is on.
func TestEgressTokenNamesTheTaskScope(t *testing.T) {
	task := &Task{ID: "7"}
	task.targetGate.Store(true)
	m := egressManager(t, task)

	token := m.EgressToken("7")
	if token == "" {
		t.Fatal("no token for an existing task")
	}
	scope, ok := m.egressScope(token)
	if !ok {
		t.Fatalf("token %q did not resolve", token)
	}
	if scope.TaskID != "7" || scope.WaitBound != 0 || scope.Interceptor != m.interceptor {
		t.Fatalf("scope = %+v, want task 7, no wait bound, this interceptor", scope)
	}
	if scope.Enabled == nil || !scope.Enabled() {
		t.Fatal("scope does not read the task's gate flag")
	}
	// The flag is read on every connection, not captured at mint time.
	task.targetGate.Store(false)
	if scope, ok := m.egressScope(token); !ok || scope.Enabled() {
		t.Fatalf("scope after the task turned the gate off: ok=%v scope=%+v", ok, scope)
	}
}

// A token is refused unless it verifies under this process's key and names a
// task the process holds.
func TestEgressTokenRefusals(t *testing.T) {
	task := &Task{ID: "7"}
	task.targetGate.Store(true)
	m := egressManager(t, task)
	token := m.EgressToken("7")

	if _, ok := m.egressScope(token + "x"); ok {
		t.Fatal("a tampered token resolved")
	}
	if _, ok := m.egressScope(""); ok {
		t.Fatal("an empty token resolved")
	}
	if _, ok := m.egressScope("t:7"); ok {
		t.Fatal("an unsigned reference resolved")
	}
	if _, ok := m.egressScope("t:8.deadbeef"); ok {
		t.Fatal("a forged token resolved")
	}
	// A token minted by another process (another key) does not verify here.
	other := egressManager(t, task)
	if _, ok := other.egressScope(token); ok {
		t.Fatal("a token of another process's key resolved")
	}
	// A token for a task this process does not hold resolves to nothing.
	if _, ok := m.egressScope(m.EgressToken("999")); ok {
		t.Fatal("a token for an unknown task resolved")
	}
	// No task, no token.
	if got := m.EgressToken(""); got != "" {
		t.Fatalf("EgressToken(\"\") = %q, want empty", got)
	}
}
