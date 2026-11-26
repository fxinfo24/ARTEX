package db

import (
	"fmt"
	"sort"
)

// NodeWindows returns, in one statement, the newest limit(kind) nodes of each
// kind in limits, newest first within a kind.
//
// The graph overview is rebuilt from the graph on every planner turn. It used to
// read the five kinds with five ListByKind calls, each `ORDER BY id DESC LIMIT n`
// over every row of its exploration.
//
// One statement, one round trip: a per-kind window is served by
// idx_expnodes_kind_id (exploration_id, kind, id DESC), which stops at the
// number of rows asked for. Measured on 32,000 interleaved nodes (27,954 facts,
// 3,200 intents, 754 findings, 57 goals, 35 hints):
//
//	five ListByKind calls            7.3 ms without the index, 5.6 ms with it
//	one statement, per-kind LIMIT    20.9 ms without the index, 2.0 ms with it
//	one statement, row_number()      41.8 ms without the index, 16.0 ms with it
//
// The row_number() shape is the slower one: it numbers every row of each kind
// on every turn before the cap is applied, so it wins nothing back from the
// index. The per-kind LIMIT in the LATERAL subquery is what lets the index stop
// early, and it is still one statement with the caps in SQL.
//
// A kind missing from limits is not read; a call without limits reads nothing.
func (s *ExplorationStore) NodeWindows(limits map[string]int) (map[string][]*Node, error) {
	if len(limits) == 0 {
		return map[string][]*Node{}, nil
	}
	kinds := make([]string, 0, len(limits))
	caps := make([]int, 0, len(limits))
	for kind, cap := range limits {
		if cap <= 0 {
			return nil, fmt.Errorf("node window: kind %q has no positive cap", kind)
		}
		kinds = append(kinds, kind)
		caps = append(caps, cap)
	}
	// A fixed order for the arrays keeps the statement identical every turn, so
	// the server plans it once.
	sort.Sort(byKindThenCap{kinds, caps})

	rows, err := s.db.Query(`
WITH caps AS (
  SELECT * FROM unnest($2::text[], $3::int[]) AS c(node_kind, cap)
)
SELECT `+nodeCols+`
FROM caps c
JOIN LATERAL (
  SELECT n.id AS node_id
  FROM exploration_nodes n
  WHERE n.exploration_id = $1 AND n.kind = c.node_kind
  ORDER BY n.id DESC
  LIMIT c.cap
) w ON true
JOIN exploration_nodes e ON e.id = w.node_id
ORDER BY e.kind, e.id DESC`, s.expID, kinds, caps)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]*Node{}
	for rows.Next() {
		n, err := scanNode(rows)
		if err != nil {
			return nil, err
		}
		out[n.Kind] = append(out[n.Kind], n)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// byKindThenCap sorts the two parallel cap arrays by kind.
type byKindThenCap struct {
	kinds []string
	caps  []int
}

func (b byKindThenCap) Len() int           { return len(b.kinds) }
func (b byKindThenCap) Less(i, j int) bool { return b.kinds[i] < b.kinds[j] }
func (b byKindThenCap) Swap(i, j int) {
	b.kinds[i], b.kinds[j] = b.kinds[j], b.kinds[i]
	b.caps[i], b.caps[j] = b.caps[j], b.caps[i]
}
