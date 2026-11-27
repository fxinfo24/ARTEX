#!/usr/bin/env python3
"""Mutation checks for boundaries the test suite is supposed to hold.

A test that passes proves nothing about the behaviour it names: it could pass for
the wrong reason, or not run at all. This script breaks the behaviour on purpose,
one narrow edit at a time, and requires the named test to fail. A mutation that
leaves the suite green is a blind spot, not a success — the script exits non-zero.

Covers the auth session boundary (change-password, login reply) and the target
gate's authorization boundary (only operator-declared scope counts).

Usage:
    python3 scripts/mutation_check.py            # all mutations
    python3 scripts/mutation_check.py auth       # only labels containing "auth"
    python3 scripts/mutation_check.py --list

Needs a Go toolchain on PATH and, for the auth and db mutations, ARTEX_PG_DSN
pointing at a disposable PostgreSQL. Without it those tests skip themselves, and a
skipped test would look like a surviving mutation, so this script refuses to run
them in that case.

The working tree must be clean for every file the script edits; it restores each
file with `git checkout --` as it goes and on SIGINT.
"""

import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GIT = ["git", "-C", ROOT]

CHANGE_PW_PREFIX = "	version, err := pg.RotatePassword(s.passwordHashKey(), string(newHash), s.passwordVersionKey())"
CHANGE_PW_FAIL = """	if err != nil {
		writeErr(w, 500, "Save failed: "+err.Error())
		return
	}"""
WRONG_PW = """	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Password)); err != nil {
		writeErr(w, 401, "Incorrect username or password")
		return
	}"""
UNAUTH_REDIRECT = """		case !authed:
			http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
			return"""


def _change_pw(old_fail=CHANGE_PW_FAIL, new_body=""):
    """The failure branch of change-password, and the same branch with `body` spliced in.

    The prefix is part of the anchor because authInit has an identical
    `if err != nil { writeErr(w, 500, "Save failed: ...") }` block."""
    return CHANGE_PW_PREFIX + "\n" + old_fail, CHANGE_PW_PREFIX + "\n" + (
        "\tif err != nil {\n" + new_body + "\n\t\treturn\n\t}" if new_body else old_fail)


MUTATIONS = [
    # --- the 500 from a failed password rotation must not end the caller's session
    dict(
        label="auth: failed password save returns a replacement token",
        boundary="session",
        file="server/auth.go",
        pkg="./server",
        test="TestChangePasswordKeepsSessionWhenSaveFails",
        old=_change_pw()[0],
        new=_change_pw(new_body='\t\ttok, _ := signJWTVersion(s.jwtKey, s.pwdVersion.Load())\n'
                              '\t\twriteJSON(w, 500, map[string]any{"ok": false, "token": tok})')[1],
    ),
    dict(
        label="auth: failed password save moves the version",
        boundary="session",
        file="server/auth.go",
        pkg="./server",
        test="TestChangePasswordKeepsSessionWhenSaveFails",
        old=_change_pw()[0],
        new=_change_pw(new_body='\t\ts.applyPasswordVersion(s.pwdVersion.Load() + 1)\n'
                              '\t\twriteErr(w, 500, "Save failed: "+err.Error())')[1],
    ),
    dict(
        label="auth: failed password save marks the password state unreadable",
        boundary="session",
        file="server/auth.go",
        pkg="./server",
        test="TestChangePasswordKeepsSessionWhenSaveFails",
        old=_change_pw()[0],
        new=_change_pw(new_body='\t\ts.pwdState.Store(pwdUnreadable)\n'
                              '\t\twriteErr(w, 500, "Save failed: "+err.Error())')[1],
    ),
    # --- the login reply
    dict(
        label="auth: login reply names the username that does not exist",
        boundary="session",
        file="server/auth.go",
        pkg="./server",
        test="TestLoginFailureReturns401WithMessage",
        old='	if req.Username != "ARTEX" {\n		writeErr(w, 401, "Incorrect username or password")',
        new='	if req.Username != "ARTEX" {\n		writeErr(w, 401, "No such user")',
    ),
    dict(
        label="auth: a wrong password is answered with 200",
        boundary="session",
        file="server/auth.go",
        pkg="./server",
        test="TestLoginFailureReturns401WithMessage",
        old=WRONG_PW,
        new='	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Password)); err != nil {\n'
            '		writeJSON(w, 200, map[string]any{})\n'
            '		return\n'
            '	}',
    ),
    dict(
        label="auth: a rejected login disturbs the live session",
        boundary="session",
        file="server/auth.go",
        pkg="./server",
        test="TestLoginFailureReturns401WithMessage",
        old=WRONG_PW,
        new='	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Password)); err != nil {\n'
            '		s.pwdState.Store(pwdUnreadable)\n'
            '		writeErr(w, 401, "Incorrect username or password")\n'
            '		return\n'
            '	}',
    ),
    # --- the console page guard
    dict(
        label="guard: unauthenticated pages are served instead of redirected",
        boundary="session",
        file="server/webui_guard.go",
        pkg="./server",
        test="TestWebuiAuthGuard",
        old=UNAUTH_REDIRECT,
        new='		case !authed:\n			// mutation: serve the page anyway',
    ),
    dict(
        label="guard: the redirect lands on the wrong path",
        boundary="session",
        file="server/webui_guard.go",
        pkg="./server",
        test="TestWebuiAuthGuard",
        old=UNAUTH_REDIRECT,
        new='		case !authed:\n			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)\n			return',
    ),
    dict(
        label="guard: a public page turns signed-in visitors away",
        boundary="session",
        file="server/webui_guard.go",
        pkg="./server",
        test="TestWebuiAuthGuard",
        old='		case webuiPublicPage(r.URL.Path):\n			if authed {',
        new='		case webuiPublicPage(r.URL.Path):\n			if !authed {',
    ),
    dict(
        label="guard: a token in the query string opens a page",
        boundary="session",
        file="server/webui_guard.go",
        pkg="./server",
        test="TestWebuiAuthGuardIgnoresQueryToken",
        old='	c, err := r.Cookie(sessionCookie)\n	if err != nil || c.Value == "" {\n		return false\n	}',
        new='	if q := r.URL.Query().Get("token"); q != "" {\n		return s.sessionOK(q)\n	}\n'
            '	c, err := r.Cookie(sessionCookie)\n	if err != nil || c.Value == "" {\n		return false\n	}',
    ),
    # --- the target gate's authorization boundary
    dict(
        label="gate: agent-written scope counts as operator authorization",
        boundary="target-gate",
        file="db/task_scope.go",
        pkg="./db",
        test="TestDeclaredScopeRowsIgnoresAgentRows",
        old="WHERE task_id=$1 AND source='manual'",
        new="WHERE task_id=$1 AND source IN ('manual','agent')",
    ),
]

NEEDS_PG = {"session", "target-gate"}


def run(cmd, env=None, timeout=600):
    return subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, env=env, timeout=timeout)


def dirty(paths):
    out = run(GIT + ["status", "--porcelain", "--"] + list(paths)).stdout
    return [line for line in out.splitlines() if line.strip()]


def restore(path):
    run(GIT + ["checkout", "--", path])


def skipped_test(output):
    return bool(re.search(r"^\s*--- SKIP|^no test files|no tests to run", output, re.M))


def main(argv):
    if "--list" in argv:
        for m in MUTATIONS:
            print(f"{m['boundary']:<12} {m['label']}")
        return 0

    filters = [a for a in argv[1:] if not a.startswith("-")]
    selected = [m for m in MUTATIONS if not filters or any(f in m["label"] or f == m["boundary"] for f in filters)]
    if not selected:
        print(f"no mutation matches {filters}", file=sys.stderr)
        return 2

    files = sorted({m["file"] for m in selected})
    clashes = dirty(files)
    if clashes:
        print("refusing to start: the working tree is not clean for these files, and the "
              "script restores them with `git checkout --`:", file=sys.stderr)
        for line in clashes:
            print("  " + line, file=sys.stderr)
        return 2

    env = dict(os.environ)
    have_pg = bool(env.get("ARTEX_PG_DSN", "").strip())
    if not have_pg:
        missing = sorted({m["boundary"] for m in selected} & NEEDS_PG)
        if missing:
            print("ARTEX_PG_DSN is not set. The tests behind these mutations skip without a "
                  f"database, and a skip would read as a surviving mutation: {', '.join(missing)}", file=sys.stderr)
            return 2

    # Baseline: every named test must pass unmodified, or a failure below proves nothing.
    print("baseline", flush=True)
    for key in sorted({(m["pkg"], m["test"]) for m in selected}):
        pkg, test = key
        res = run(["go", "test", pkg, "-run", f"^{test}$", "-count=1"], env=env)
        if res.returncode != 0 or skipped_test(res.stdout + res.stderr):
            sys.stdout.write(res.stdout[-3000:] + res.stderr[-2000:])
            print(f"FAIL baseline {pkg} {test}: the test does not pass unmodified", file=sys.stderr)
            return 1
        print(f"  ok  {pkg} {test}", flush=True)

    survivors = []
    try:
        for m in selected:
            with open(os.path.join(ROOT, m["file"]), encoding="utf-8") as fh:
                original = fh.read()
            hits = original.count(m["old"])
            if hits != 1:
                print(f"  ANCHOR {m['label']}: matched {hits} times in {m['file']}, expected 1", file=sys.stderr)
                survivors.append(m)
                continue
            with open(os.path.join(ROOT, m["file"]), "w", encoding="utf-8") as fh:
                fh.write(original.replace(m["old"], m["new"], 1))
            try:
                res = run(["go", "test", m["pkg"], "-run", f"^{m['test']}$", "-count=1"], env=env)
            finally:
                restore(m["file"])
            if res.returncode == 0:
                print(f"  SURVIVED  {m['label']}  ({m['test']} still green)", flush=True)
                survivors.append(m)
            elif skipped_test(res.stdout + res.stderr):
                print(f"  SKIPPED   {m['label']}  ({m['test']} skipped under mutation)", flush=True)
                survivors.append(m)
            else:
                print(f"  caught    {m['label']}", flush=True)
    except KeyboardInterrupt:
        print("interrupted, restoring", file=sys.stderr)
        return 130
    finally:
        for path in files:
            restore(path)

    left = dirty(files)
    if left:
        print("restore failed for:", left, file=sys.stderr)
        return 1

    total = len(selected)
    if survivors:
        print(f"\n{len(survivors)}/{total} mutations survived — the suite does not cover what they break:", file=sys.stderr)
        for m in survivors:
            print(f"  - {m['label']}", file=sys.stderr)
        return 1
    print(f"\nall {total} mutations caught")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
