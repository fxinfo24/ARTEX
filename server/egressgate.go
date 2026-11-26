package server

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/Autumn-27/artex/intercept"
	"github.com/Autumn-27/artex/traffic"
)

// A Bash subcommand reaches targets through the recording proxy, and the proxy
// dials for it: the target gate never saw that address (traffic/gate.go). The
// gate relay closes the gap, but it has to know which session a proxied
// connection belongs to — a connection the proxy received is otherwise
// anonymous. The proxy URL handed to a task's Bash environment carries a session
// token in its userinfo for that (egress.MarkProxyURLToken); the recording proxy
// passes it to the relay, and the relay resolves it here.
//
// The token is stateless: "t:<task id>.<HMAC-SHA256 of that reference under a
// key generated at startup>". Nothing is stored per task, a token cannot be
// forged without the process key, and a token of a task this process does not
// know resolves to nothing — the connection is refused rather than admitted
// under a scope that no longer exists. The key dies with the process, so a
// token in an environment copied out of a container stops working at restart.

const egressRefSeparator = "."

// egressGateSecret keys the session tokens of this process.
func newEgressGateSecret() ([]byte, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("egress gate: generate the session token key: %w", err)
	}
	return secret, nil
}

// EgressToken returns the session token of task taskID, or "" for no task.
func (m *Manager) EgressToken(taskID string) string {
	if strings.TrimSpace(taskID) == "" || len(m.egressSecret) == 0 {
		return ""
	}
	return signEgressRef(m.egressSecret, "t:"+taskID)
}

func signEgressRef(secret []byte, ref string) string {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(ref))
	return ref + egressRefSeparator + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)[:16])
}

// egressScope resolves a session token to the target scope of the task it names.
// ok is false for any token that does not verify or names a task this process
// does not hold: the gate relay refuses such a connection.
func (m *Manager) egressScope(token string) (intercept.TargetScope, bool) {
	ref, sig, ok := strings.Cut(token, egressRefSeparator)
	if !ok || ref == "" || sig == "" {
		return intercept.TargetScope{}, false
	}
	want := signEgressRef(m.egressSecret, ref)
	_, wantSig, _ := strings.Cut(want, egressRefSeparator)
	if subtle.ConstantTimeCompare([]byte(sig), []byte(wantSig)) != 1 {
		return intercept.TargetScope{}, false
	}
	kind, id, ok := strings.Cut(ref, ":")
	if !ok || kind != "t" || id == "" {
		return intercept.TargetScope{}, false
	}
	t, ok := m.Task(id)
	if !ok || t == nil {
		return intercept.TargetScope{}, false
	}
	// WaitBound 0: a connection never waits for a decision. The request stays
	// open, and the retry after the approval dials through (the same rule the
	// gate applies to PinnedDialer's own dial).
	return intercept.TargetScope{
		TaskID:             t.ID,
		Enabled:            t.targetGate.Load,
		WaitBound:          0,
		Interceptor:        m.interceptor,
		AssessmentIdentity: t.assessmentIdentity,
	}, true
}

// egressGateDial is the dial of the gate relay: the platform's target gate on
// the address the connection names, with the approved addresses connected
// through the configured global egress proxy (traffic.DialUpstream) rather than
// straight out.
func (m *Manager) egressGateDial(ctx context.Context, network, addr string) (net.Conn, error) {
	if m.traffic != nil {
		ctx = intercept.WithDialOverride(ctx, m.traffic.DialUpstream)
	}
	return m.interceptor.DialSOCKS5(ctx, network, addr)
}

// startEgressGate installs the gate relay of the recording proxy. It does
// nothing without a recording proxy: with capture off the agents dial the
// global proxy themselves and the gate relay has no connection to decide.
func (m *Manager) startEgressGate() {
	if m.traffic == nil {
		return
	}
	if err := m.traffic.SetEgressGate(traffic.GateConfig{
		Resolve: m.egressScope,
		Dial:    m.egressGateDial,
	}); err != nil {
		log.Printf("[traffic/gate] disabled, proxied Bash traffic stays ungated: %v", err)
		return
	}
	log.Printf("[traffic/gate] recording proxy dials through the target gate on %s", m.traffic.GateAddr())
}
