package db

import (
	"encoding/json"
	"testing"
)

// The overview reads every kind it needs in one statement (db.NodeWindows): each
// kind's newest window, newest first, and nothing for a kind not asked for.
func TestNodeWindowsReturnsNewestPerKind(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		SkipPGUnavailable(t, err)
	}
	defer d.Close()

	expID, err := d.CreateExploration("test", "node windows")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM explorations WHERE id=$1`, expID) //nolint:errcheck
	es := d.Exploration(expID)

	// Interleaved, the way a running scan writes them: the ids of one kind are
	// scattered, so a window has to select by kind and order, not by position.
	var facts, intents []int64
	add := func(kind, state, summary string) int64 {
		t.Helper()
		id, err := es.AddNode(kind, map[string]any{"summary": summary}, 0, state, "test", nil)
		if err != nil {
			t.Fatalf("add %s: %v", kind, err)
		}
		return id
	}
	for i := range 7 {
		facts = append(facts, add(KindFact, "confirmed", "fact"))
		if i < 5 {
			intents = append(intents, add(KindIntent, "open", "intent"))
		}
		if i < 2 {
			add(KindGoal, "open", "goal")
		}
	}
	add(KindHint, "active", "hint")

	got, err := es.NodeWindows(map[string]int{KindFact: 3, KindIntent: 2, KindFinding: 4})
	if err != nil {
		t.Fatalf("NodeWindows: %v", err)
	}
	if len(got[KindFinding]) != 0 {
		t.Fatalf("findings = %d, want none (there are none)", len(got[KindFinding]))
	}
	if _, ok := got[KindGoal]; ok {
		t.Fatal("a kind that was not asked for came back")
	}
	// Newest first: the window is id DESC.
	want := map[string][]int64{
		KindFact:   {facts[6], facts[5], facts[4]},
		KindIntent: {intents[4], intents[3]},
	}
	for kind, ids := range want {
		nodes := got[kind]
		if len(nodes) != len(ids) {
			t.Fatalf("%s window = %d nodes, want %d", kind, len(nodes), len(ids))
		}
		for i, id := range ids {
			if nodes[i].ID != id {
				t.Fatalf("%s window[%d] = %d, want %d (newest first)", kind, i, nodes[i].ID, id)
			}
		}
	}
	// The payload comes back decoded, not as a window id.
	var payload map[string]any
	if err := json.Unmarshal(got[KindFact][0].Payload, &payload); err != nil || payload["summary"] != "fact" {
		t.Fatalf("payload = %s, %v", got[KindFact][0].Payload, err)
	}

	// No limits, no read.
	if empty, err := es.NodeWindows(nil); err != nil || len(empty) != 0 {
		t.Fatalf("NodeWindows(nil) = %v, %v", empty, err)
	}
	// A window of zero rows is a caller error, not a silent full read.
	if _, err := es.NodeWindows(map[string]int{KindFact: 0}); err == nil {
		t.Fatal("NodeWindows with a zero cap did not fail")
	}
}
