package agent

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

// TestCredentialOverviewNeverCarriesThePassword: the overview is injected into the
// worker's context on every round, so a password in it is re-sent with every call
// and copied into every transcript. The block names the accounts and says whether a
// password exists; the value stays behind list_task_credentials.
func TestCredentialOverviewNeverCarriesThePassword(t *testing.T) {
	const secret = "s3cret-hunter2"
	rows := credentialOverviewRows([]db.TaskCredential{
		{Domain: "app.example.com", Username: "alice", Password: secret, Source: "manual", Note: "program alias"},
		{Domain: "app.example.com", Username: "bob", Password: "", Source: "manual"},
	})
	if len(rows) != 2 {
		t.Fatalf("rows = %d, want 2", len(rows))
	}

	blob, err := json.Marshal(rows)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(blob), secret) {
		t.Fatalf("the overview carries the password: %s", blob)
	}
	if _, ok := rows[0]["password"]; ok {
		t.Fatal("the overview still sets a password field")
	}

	if rows[0]["password_set"] != true {
		t.Fatalf("entry with a stored password: password_set=%v, want true", rows[0]["password_set"])
	}
	if rows[1]["password_set"] != false {
		t.Fatalf("entry without a password: password_set=%v, want false", rows[1]["password_set"])
	}

	// The model must be told where the value lives, or it will register a duplicate
	// account instead of signing in with the one it already has.
	if got := rows[0]["instruction"].(string); !strings.Contains(got, "list_task_credentials") {
		t.Fatalf("instruction for a stored password does not point at list_task_credentials: %q", got)
	}
	if got := rows[1]["instruction"].(string); !strings.Contains(got, "save_task_credential") {
		t.Fatalf("instruction for a missing password does not say to record it: %q", got)
	}

	// Operator notes are context, not secrets, and stay.
	if rows[0]["note"] != "program alias" {
		t.Fatalf("note = %v, want the operator's", rows[0]["note"])
	}
}
