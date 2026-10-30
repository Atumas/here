# Visual AI Agent Workbench — Fedora 44 / KDE Plasma Edition

> **Upstream:** https://github.com/Atumas/here · **Release:** v1.0.0-desktop (last fixed desktop version — no mobile/APK companion, no external prompt artifacts)

**Zero-dependency, single-file browser GUI (`index.html`) + hardened local WebSocket bridge (`bridge_daemon.py`)**
that compiles visual node graphs into Bash scripts and streams them into `/bin/bash` over stdin — with a five-level
Zero-Trust security pipeline. No `.sh` files are ever written to disk. No npm/pip packages required.

---

## 1. Repository Contents

| File | Role | Lines |
|---|---|---|
| `index.html` | Complete SPA workbench GUI (UI + sanitizer + registry + compiler + router + state store) | ~2,039 |
| `bridge_daemon.py` | Hardened stdlib-only Python WebSocket→Bash execution bridge (Level-4/5 ring) | ~179 |

---

## 2. Architecture: The Five-Level Zero-Trust Pipeline

```
[ BROWSER SANDBOX — index.html ]
  Level 1  In-browser input sanitization      SecurityShieldSanitizer.sanitizeShellString()
  Level 2  Structured JSON serialization      buildWorkflowJSON()   (metadata only, no raw code)
  Level 3  Adversarial validation + dry-run   evaluateScriptSafetyScore() + L3 artifact gate
─────────────── ws://localhost:8080 ───────────────
[ HOST — bridge_daemon.py ]
  Level 4  Daemon payload validation          validate_frame(): schema, token, size, shebang,
                                              banned binaries, substitution whitelist, path jail
  Level 5  Volatile shell ingestion           echo "$SCRIPT" | /bin/bash   (stdin pipe, zero footprint)
─────────────── streamed STDOUT/STDERR/EXIT frames back to GUI console ───────────────
```

Every phase is independently defensive: a threat must defeat **five separate validators** before it can touch the OS,
and Defensive Visualizer Mode (dry-run) halts transmission entirely at Level 3 by default.

---

## 3. Getting Started (Fedora 44 / KDE)

```bash
# Terminal 1 — start the bridge daemon (stdlib only, no pip installs):
python3 ~/workbench/bridge_daemon.py
# → "BRIDGE ONLINE · ws://127.0.0.1:8080 · interpreter=/usr/bin/bash"

# Terminal 2 — open the GUI in any browser:
xdg-open ~/workbench/index.html
```

In the GUI topbar: **CONNECT** (WebSocket handshake), confirm *Defensive Visualizer Mode* is ARMED, build a graph,
press **COMPILE → DRY-RUN**, inspect artifacts, then disarm dry-run and press **EXECUTE VIA BRIDGE**.

Optional: install Ollama (`ollama pull llama3.2`) to let `ollama_inference` nodes run real models; without it the
compiled script halts gracefully via its own `set -e` guard, which is expected behavior.

---

## 4. Layout Map & Function Index (`index.html`)

### 4.1 Shell chrome
- **Topbar** (~line 285): brand, live connection LED, threat-intercept counter, `Defensive Visualizer Mode` toggle,
  CONNECT / COMPILE→DRY-RUN / EXECUTE-VIA-BRIDGE buttons.
- **Sidebar `<nav id="sidebar">`** (lines 302–310): six router entries, each `data-route` ↔ template pair:

| Route | Template (`id=`) | Line | What it contains |
|---|---|---|---|
| `canvas` | `visual-node-canvas-view` | 326 | HTML5-canvas node editor: drag-drop palette (file_reader / ollama_inference / directory_list), draggable nodes, bezier port links, property inspector form, compiled-artifact panels |
| `chat` | `live-chat-terminal-view` | 383 | Directive chat input → workflow parser, scrolling console that renders streamed STDOUT/STDERR/EXIT frames from the daemon |
| `security` | `security-audit-view` | 411 | Live audit log, safety-score gauge, per-level verdict history, quarantine buffer, "Reactive Router State / Memory Store Snapshot" debug panel (line 397 lives in canvas view) |
| `emulation` | `attack-emulation-view` | 446 | **Security Emulation Console Room**: 8 preset adversarial payloads + benign control + "FIRE FULL SUITE", per-stage interception trace table |
| `docs` | `documentation-view` | 485 | Full systems documentation (Section 5 Module C matrix) rendered natively |
| `settings` | `settings-view` | 545 | Bridge URL/token, model name, default paths, theme accents, reset-store action |

### 4.2 JavaScript namespaces (what to look for when reviewing)

| Symbol | Line | Responsibility |
|---|---|---|
| `AppStore` | 581 | Global volatile memory: `{connection, settings, graph:{nodes,links}, chatLog, audit:{threatsBlocked,history,quarantine}, artifacts:{json,bash}}`. Survives every view swap untouched. |
| `SecurityShieldSanitizer` | 624 | **Level 1.** `blacklistTokens` regex array (`;\s*rm`, `>\s*/etc`, `|\sbash`, `nc\s+-e`, `chown`, `chmod 777`, fork-bomb, prompt-injection grammar); `sanitizeShellString()` escape chain `\ $ \` "` + semicolon entity-encoding; `evaluateScriptSafetyScore()` → `{isPassed, score, identifiedRisks}`. |
| `CoreTaskCodeRegistry` | 816 | **Task 1 registry.** Per-node-type `generateBashSegment(properties)` builders: `file_reader` (`[[ -f ]]`/`[[ -r ]]` guards → `$INPUT_DATA_STREAM`), `ollama_inference` (masked vars + `<<WORKBENCH_EOF` heredoc → `ollama run "$MODEL" --system …`), `directory_list` (`ls -la --color=always --group-directories-first "$TARGET_SCAN_ROUTE"`). |
| `buildWorkflowJSON()` | 939 | **Level 2.** Collects active form fields/graph order → sequential immutable JSON node array (pure metadata). |
| `compileWorkflowToBash(workflowJSON)` | 974 | **Compiler core.** Emits `#!/bin/bash` header block, `set -e` + `set -o pipefail`, buffer initializers, loops registry segments, `[COMPILER_WARNING]` for unknown node types, trailer + `exit 0`. |
| L3 artifact gate | ~1000+ | Scans the finished Bash string: forbidden binaries, `/etc/passwd|shadow`, `/dev/tcp` shells, non-whitelisted `$( )`, quote-aware raw-semicolon detection, foreign heredocs, size budget. Fail ⇒ quarantine + abort send. |
| Network layer | 1020–1075 | `ws://localhost:8080` handshake, frame sender (line 1050: `{type:"EXECUTE_BASH_STRING", token:"workbench-local-session", payload:{script,bytes}}`), inbound dispatcher for `STDOUT|STDERR|EXIT|RESULT|LOG` frames. |
| `Router` | 1245 | **Task 2.** Template-swapper using `content.cloneNode(true)` only — no reloads; hash-synced; canvas rebind hook at line 1309. |
| Boot | 2031 | `Router.init()` wires sidebar clicks, templates, and default view. |

### 4.3 Review checklist (suggested click-path)
1. Canvas: drop all three node types → link them → edit inspector fields with hostile text like `"; rm -rf / #` → watch Level-1 neutralize it inline.
2. COMPILE → DRY-RUN: verify JSON tree + Bash artifact panels render, header/guards present, no network activity while ARMED.
3. Attack Emulation → FIRE FULL SUITE: expect 8/8 INTERCEPTED, benign control CLEAN, topbar threat counter increments.
4. Settings: change bridge URL/token, reconnect, check the LED + handshake log line.
5. Chat: type `read ./notes.txt then summarize with llama3.2 then list .` → confirm directive parser builds the same JSON the canvas does.

---

## 5. Wire Protocol (GUI ⇄ Daemon)

**Outbound (browser → daemon), one text frame:**
```json
{"type":"EXECUTE_BASH_STRING","token":"workbench-local-session",
 "payload":{"script":"#!/bin/bash\nset -e\n…","bytes":453}}
```
**Inbound (daemon → browser):** `{"type":"LOG","message":…}`, `{"type":"RESULT","message":"level-4 verdict: …"}`,
`{"type":"STDOUT","line":…}`, `{"type":"STDERR","line":…}`, `{"type":"EXIT","code":N}` — streamed line-by-line.

Daemon rejects before evaluation on: size > 64 KiB, malformed JSON, wrong `type`/`token`, payload field-type
violation, missing shebang/`set -e`/`pipefail`, banned binaries (`sudo nc curl wget mkfs dd chown eval crontab…`),
`/etc/passwd|shadow`, `/dev/tcp|udp`, `| bash`, backticks, non-whitelisted `$(`, illegal `;`/`&` outside quoted
literals or allow-listed control-flow lines, path-jail violations (relative paths resolve under `WORK_ROOT=/tmp`).

---

## 6. Verification Evidence (all re-run on 2026-10-18)

| Suite | Result |
|---|---|
| GUI harness (compiler shapes, sanitizer escaping/blocking, L3 pass/block, 8 attack presets, benign control, dry-run zero-transmission, AppStore survival across router swaps) | **29/29 PASS** |
| Daemon validator unit suite vs. real GUI-shaped frames (benign ACCEPT; curl dropper, `$(cat /etc/shadow)`, sudo, `/dev/tcp` reverse shell, bad token, malformed JSON, oversize — all REJECT) | **8/8 PASS** |
| End-to-end: real WS handshake → daemon Level-4 accept → live `/bin/bash` stdin execution → streamed frames (`captured 33 octets`, `ls` listing, `EXIT: 0`) | **PASS** |
| `py_compile bridge_daemon.py` / `node --check` extracted JS core | **PASS** |

Bugs found & fixed during this final verification pass (in `bridge_daemon.py`): stale `$( )` whitelist not covering
`ollama run`/`ls` capture forms; `>&2` stderr redirects falsely flagged as background operators; `else`/`exit N`
control-flow lines rejected; relative `./path` failing the absolute-path policy (now normalized against `WORK_ROOT`);
`read_frame` byte-vs-int indexing crash; two un-awaited `writer.write` coroutines that killed the connection handler
after the first verdict/stream line. All fixes confirmed by the suites above.

---

## 7. Troubleshooting

| Symptom | Cause / Fix |
|---|---|
| LED red after CONNECT | Daemon not running or port taken: `ss -tlnp \| grep 8080`, restart `bridge_daemon.py`. |
| "level-4 verdict: frame schema/token mismatch" | Token in Settings ≠ daemon `ALLOWED_TOKEN`. |
| Benign script rejected "unauthorized command substitution" | You edited node properties to inject `$(…)`; remove it — only compiler-generated capture forms are whitelisted. |
| `EXIT: 127` + `ollama: command not found` | Expected without Ollama; install it or delete the inference node. |
| Path policy violation on `/home/…` | Daemon jails to `WORK_ROOT=/tmp`; edit `WORK_ROOT` in `bridge_daemon.py` to widen deliberately. |

## 8. Security Notes & Limitations
- The bridge is a **local-trust** tool: shared secret token, loopback bind only. It is not a substitute for OS sandboxing; run under a dedicated user if multi-user.
- Whitelist-based substitution/path checks are intentionally over-strict (fail-closed): false rejections of hand-edited exotic scripts are by design.
- Browser file access is subject to `file://` origin rules; if your distro blocks `ws://` from `file://`, serve the GUI with `python3 -m http.server 9000` and open `http://localhost:9000`.

---

## 9. Scope & Roadmap Notes (v1.0.0-desktop)

**Deliberately excluded from this release:**
- 📱 **Mobile / Android APK companion** — a WebView-wrapped variant and an opt-in `--lan` daemon mode were prototyped during development and are preserved on the `master` branch history (`android-build/`, `mobile-app/`) for possible future revival, but are **not** part of this hardened desktop cut. LAN rebinding widens the attack surface and was never carried through the full Level-4 validator re-test, so it stays out.
- 🤖 External LLM-prompt artifacts (e.g., generated prompts for third-party coding agents) — kept outside the repo; they are not runtime code.
- 🔌 KDE Connect / P2P / e-mail transports — evaluated and rejected: KDE Connect's brokered relay adds a third-party trust hop and has a history of pairing-channel CVEs; any transport that isn't loopback WebSocket bypasses the Level-4 token/schema gate this design depends on.

**Planned next:** signed git tag `v1.0.0`; optional TLS/WSS local binding; plugin contract so agent-repo integrations link in without modifying `index.html`.
