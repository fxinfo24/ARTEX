package db

import (
	"fmt"
	"testing"
)

func TestCoverageEnabledWithoutTask(t *testing.T) {
	on, err := (&AssetStore{}).CoverageEnabled(0)
	if err != nil || !on {
		t.Fatalf("enabled=%v err=%v", on, err)
	}
}

func TestCoverageEnabledMissingRowStaysOn(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		SkipPGUnavailable(t, err)
	}
	defer d.Close()
	on, err := d.Assets().CoverageEnabled(9_000_000_000_001)
	if err != nil || !on {
		t.Fatalf("missing task: enabled=%v err=%v, want enabled with no error", on, err)
	}
}

func TestCoverageEnabledQueryErrorStaysOn(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		SkipPGUnavailable(t, err)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	on, err := d.Assets().CoverageEnabled(1)
	if err == nil || !on {
		t.Fatalf("failed query: enabled=%v err=%v, want enabled and the error", on, err)
	}
}

// TestStripHostPort covers the ip:port / [ipv6]:port stripping used by the
// ip/cidr scope path so a target like "10.0.188.136:3000" no longer 404s.
func TestStripHostPort(t *testing.T) {
	cases := []struct{ in, want string }{
		{"10.0.188.136:3000", "10.0.188.136"},       // the reported IP case
		{"10.0.188.136", "10.0.188.136"},            // bare IPv4 unchanged
		{"[2001:db8::1]:8080", "2001:db8::1"},       // bracketed IPv6 + port
		{"2001:db8::1", "2001:db8::1"},              // bare IPv6 unchanged (has colons)
		{" 1.2.3.4:80 ", "1.2.3.4"},                 // trims surrounding space
		{"example.com:443", "example.com"},          // domain + port → bare host
		{"api.example.com:8080", "api.example.com"}, // subdomain + port
		{"example.com", "example.com"},              // bare domain unchanged
	}
	for _, c := range cases {
		if got := stripHostPort(c.in); got != c.want {
			t.Errorf("stripHostPort(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestAddAgentScopeReturnsStoredID: the create path answers with the row it wrote.
// It used to return the struct it built, whose ID was never set, so the API
// answered id=0 and a client could not delete the row it had just added; a repeat
// add (ON CONFLICT DO NOTHING) must still answer with the existing row's id.
func TestAddAgentScopeReturnsStoredID(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		SkipPGUnavailable(t, err)
	}
	// Cleanups run last-in-first-out, so closing is registered first: the task
	// cleanup below still needs the connection.
	t.Cleanup(func() { _ = d.Close() })
	task, err := d.CreateTaskWithOptions("scope id", "goal", TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cleanupErr(t, "task", d.DeleteTask(task.ID)) })
	assets := d.Assets()
	domain := fmt.Sprintf("scope-id-%d.invalid", task.ID)

	first, err := assets.AddAgentScope(task.ID, "root_domain", domain, "test", "manual")
	if err != nil {
		t.Fatal(err)
	}
	if first.ID <= 0 {
		t.Fatalf("AddAgentScope returned id=%d, want the stored row id", first.ID)
	}
	rows, err := assets.ListTaskScope(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, r := range rows {
		if r.ID == first.ID && r.Domain == domain && r.Source == "manual" {
			found = true
		}
	}
	if !found {
		t.Fatalf("id %d does not name a stored %q scope row: %+v", first.ID, domain, rows)
	}
	again, err := assets.AddAgentScope(task.ID, "root_domain", domain, "duplicate", "manual")
	if err != nil {
		t.Fatal(err)
	}
	if again.ID != first.ID {
		t.Fatalf("repeat add returned id=%d, want the existing row id %d", again.ID, first.ID)
	}
}

// TestDeclaredScopeRowsIgnoresAgentRows guards the boundary the connect-time
// target gate depends on: only operator declarations authorize a dial. The agent
// can write its own scope rows (source='agent'), and if DeclaredScopeRows ever
// stopped filtering them the agent could authorize any target by declaring it
// first — the gate would then never ask the operator.
func TestDeclaredScopeRowsIgnoresAgentRows(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		SkipPGUnavailable(t, err)
	}
	t.Cleanup(func() { _ = d.Close() })
	task, err := d.CreateTaskWithOptions("declared scope", "goal", TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cleanupErr(t, "task", d.DeleteTask(task.ID)) })
	assets := d.Assets()

	declared := fmt.Sprintf("declared-%d.invalid", task.ID)
	selfDeclared := fmt.Sprintf("agent-%d.invalid", task.ID)
	if _, err := assets.AddAgentScope(task.ID, "root_domain", declared, "operator decision", "manual"); err != nil {
		t.Fatal(err)
	}
	if _, err := assets.AddAgentScope(task.ID, "root_domain", selfDeclared, "agent decided this itself", "agent"); err != nil {
		t.Fatal(err)
	}

	// Control: both rows exist, so an empty DeclaredScopeRows result below cannot be
	// explained by a failed insert.
	all, err := assets.ListTaskScope(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Fatalf("stored scope rows = %d, want 2 (the test needs the agent row to exist)", len(all))
	}

	rows, err := d.DeclaredScopeRows(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("DeclaredScopeRows returned %d rows, want only the operator's: %+v", len(rows), rows)
	}
	if rows[0].Domain != declared {
		t.Fatalf("DeclaredScopeRows returned %q, want the operator's %q (the agent row must not authorize a target)", rows[0].Domain, declared)
	}
	if rows[0].Source != "manual" {
		t.Fatalf("declared row source = %q, want manual", rows[0].Source)
	}
	for _, r := range rows {
		if r.Domain == selfDeclared {
			t.Fatal("an agent-written scope row reached the gate's declared set: the agent would authorize its own targets")
		}
	}

	// ScopeCoversHost still says the agent row covers the host — the filter, not the
	// matcher, is what keeps it out of authorization.
	if !ScopeCoversHost(TaskScope{Kind: "root_domain", Domain: selfDeclared}, selfDeclared, "") {
		t.Fatal("ScopeCoversHost should cover its own domain; the exclusion belongs to DeclaredScopeRows")
	}
}
