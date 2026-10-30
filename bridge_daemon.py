#!/usr/bin/env python3
"""
Visual AI Agent Workbench — Hardened Local Bridge Daemon (Task 3)
==================================================================
Fedora 44 / KDE Plasma. Stdlib-only WebSocket gateway (RFC 6455 server side)
that receives EXECUTE_BASH_STRING frames, re-validates them at Level 4, and
pipes the script text directly into /bin/bash over stdin — volatile-memory
execution, zero .sh files ever written to disk.

Run:   python3 bridge_daemon.py            (listens on ws://localhost:8080)
Stop:  Ctrl+C
"""
import os
import asyncio, base64, hashlib, json, os, re, shutil, signal, struct, subprocess

HOST, PORT, MAX_FRAME, MAX_SCRIPT = "127.0.0.1", 8080, 2 ** 20, 65536
GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
WORK_ROOT = "/tmp"   # jail root: relative GUI paths resolve here
ALLOWED_TYPE, ALLOWED_TOKEN = "EXECUTE_BASH_STRING", "workbench-local-session"
BAN = re.compile(r"\b(sudo|su\s+-|nc|ncat|telnet|curl|wget|mkfs|dd\s+if=|chown|chmod\s+777|"
                 r"eval|crontab|history\s+-c)\b|\|\s*(ba)?sh\b|/etc/(passwd|shadow)|"
                 r"/dev/(tcp|udp)/|rm\s+(-[a-zA-Z]*\s+)*-?[rf]\s+/|`")
BAN_CMDS = {"rm", "sudo", "su", "nc", "ncat", "telnet", "curl", "wget", "dd", "mkfs",
            "chown", "eval", "crontab", "shutdown", "reboot", "kill", "base64"}
SAFE_PATHS = re.compile(r'^(/[^\x00"`$;|&<>]+|~/[^\x00"`$;|&<>]+|\./[^\x00"`$;|&<>]+)$')


def validate_frame(raw: bytes):
    """Level-4 gate: strict schema + content policy. Returns (ok, reason, script)."""
    if len(raw) > MAX_SCRIPT:
        return False, f"oversized payload ({len(raw)} B > {MAX_SCRIPT} B cap)", ""
    try:
        msg = json.loads(raw.decode("utf-8"))                      # reject malformed JSON
    except Exception:
        return False, "malformed JSON envelope", ""
    if not isinstance(msg, dict) or msg.get("type") != ALLOWED_TYPE or msg.get("token") != ALLOWED_TOKEN:
        return False, "frame schema/token mismatch — packet rejected before evaluation", ""
    p = msg.get("payload")
    if not isinstance(p, dict) or not isinstance(p.get("script"), str) or not isinstance(p.get("bytes"), int):
        return False, "payload field type violation", ""
    s = p["script"]
    if not s.startswith("#!/bin/bash") or "set -e" not in s or "set -o pipefail" not in s:
        return False, "script fails structural guards (shebang/set -e/pipefail)", ""
    body = "\n".join(re.sub(r"^\s*#.*$", "", ln) for ln in s.splitlines())   # strip comments
    if BAN.search(body):
        return False, "forbidden binary / substitution / redirection pattern detected", ""
    # Command-substitution check with a compiler whitelist: only the two known
    # capture-assignment forms may open a $( ; everything else is hostile residue.
    # Whitelist compiler capture forms: $(cat ...), OUTPUT_DATA_BUFFER=$(ollama run ...),
    # ls-capture assignments, and empty INPUT_DATA_STREAM="" initializers.
    probe = re.sub(r'(?:OUTPUT_DATA_BUFFER|INPUT_DATA_STREAM)=\$\((?:cat |ollama run |ls )', "", body)
    probe = re.sub(r'(?:OUTPUT_DATA_BUFFER|INPUT_DATA_STREAM)=""', "", probe)
    if re.search(r"\$\(", probe):
        return False, "unauthorized command substitution $( ) detected", ""
    # Statement hygiene: control characters are legal ONLY inside double quotes
    # and on the compiler's own allow-listed control-flow lines.
    CTRL_OK = re.compile(r'^\s*(?:if\s|elif\s|then\b|else\b|fi\b|done\b|esac\b|\}|'
                         r'exit\s+\d+|\)|'
                         r'(?:INPUT_DATA_STREAM|OUTPUT_DATA_BUFFER)=\$?\(|'
                         r'.*\)\s*$|.*<<WORKBENCH_EOF)')
    for ln in body.splitlines():
        code = re.sub(r'"[^"]*"', '""', ln.split("#", 1)[0])
        if any(ch in code for ch in ";<>&"):
            stripped = re.sub(r"[\"$]", "", code)          # unquoted $VAR tokens stay inert data
            if ";" in stripped and not CTRL_OK.match(ln):
                return False, f"illegal statement-splitting semicolon: {ln.strip()[:60]!r}", ""
            if "&" in stripped.replace("&&", "").replace(">&2", "") and not CTRL_OK.match(ln):
                return False, f"illegal background/fork operator: {ln.strip()[:60]!r}", ""
            if ("<" in stripped or ">" in stripped) and not CTRL_OK.match(ln) \
                    and not re.search(r">&2\s*$|<<WORKBENCH_EOF|-\w+", stripped):
                return False, f"illegal redirection outside quoted literal: {ln.strip()[:60]!r}", ""
    for var in ("TARGET_FILE_CONTEXT", "OLLAMA_TARGET_MODEL", "OLLAMA_SYSTEM_INSTRUCTION", "TARGET_SCAN_ROUTE"):
        m = re.search(var + r'="([^"]*)"', s)
        if m:
            v = m.group(1)
            if var != "OLLAMA_SYSTEM_INSTRUCTION":
                vabs = os.path.normpath(os.path.join(WORK_ROOT, v)) if not v.startswith("/") else v
                if (".." in v or re.search(r"(^|/)(bin|sbin|boot|dev|proc|sys|usr|etc|var)(/|$)", vabs)
                        or not SAFE_PATHS.match(vabs)):
                    return False, f"path policy violation in {var}: {v[:60]!r}", ""
            if len(v.encode()) > 4096:
                return False, f"{var} exceeds field budget", ""
    for tok in re.findall(r"(?:^|\|)\s*([a-z][\w\-\.]*)", body, re.M):
        if tok in BAN_CMDS:
            return False, f"blocked command token: {tok}", ""
    return True, "accepted", s


async def read_frame(reader):
    h1 = await reader.readexactly(1); h2 = await reader.readexactly(1)
    op = h1[0] & 0x0F; ln = h2[0] & 0x7F; mask = (h2[0] >> 7) & 1
    if ln == 126: ln = struct.unpack("!H", await reader.readexactly(2))[0]
    elif ln == 127: ln = struct.unpack("!Q", await reader.readexactly(8))[0]
    if ln > MAX_FRAME: raise ValueError("frame too large")
    mk = await reader.readexactly(4) if mask else b""
    d = await reader.readexactly(ln) if ln else b""
    if mask: d = bytes(b ^ mk[i % 4] for i, b in enumerate(d))
    return op, d


def frame(op, data=b""):
    out = bytearray([0x80 | op])
    n = len(data)
    if n < 126: out.append(n)
    elif n < 2 ** 16: out += bytes([126]) + struct.pack("!H", n)
    else: out += bytes([127]) + struct.pack("!Q", n)
    return bytes(out) + data


async def stream_pipe(pipe, writer, tag):
    loop = asyncio.get_running_loop()
    while True:
        line = await loop.run_in_executor(None, pipe.readline)
        if not line: break
        txt = line.decode("utf-8", "replace").rstrip("\r\n")
        clean = "".join(c for c in txt if c >= " " or c == "\t")[:4000]
        writer.write(frame(1, json.dumps({"type": tag, "line": clean}).encode()))
        await writer.drain()


async def handle(reader, writer):
    peer = writer.get_extra_info("peername")
    key = None
    try:                                          # --- HTTP/WS handshake ---
        req = (await reader.readuntil(b"\r\n\r\n")).decode("latin-1")
        for h in req.splitlines():
            if h.lower().startswith("sec-websocket-key:"): key = h.split(":", 1)[1].strip()
        if not key: writer.close(); return
        acc = base64.b64encode(hashlib.sha1(key.encode() + GUID).digest()).decode()
        writer.write(("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                      f"Connection: Upgrade\r\nSec-WebSocket-Accept: {acc}\r\n\r\n").encode())
        await writer.drain()
        bash = shutil.which("bash") or "/bin/bash"
        writer.write(frame(1, json.dumps({"type": "LOG", "message": f"bridge ready · interpreter={bash} · pid={os.getpid()}"}).encode()))
        await writer.drain()
        while True:                               # --- message loop ---
            op, data = await read_frame(reader)
            if op == 8: break                     # close
            if op == 9: await writer.write(frame(10, data)); continue   # ping->pong
            if op != 1: continue
            ok, why, script = validate_frame(data)
            async def send(o):
                writer.write(frame(1, json.dumps(o).encode())); await writer.drain()
            await send({"type": "RESULT", "message": f"level-4 verdict: {why}"})
            if not ok:
                print(f"[BRIDGE] REJECT from {peer}: {why}")
                continue
            print(f"[BRIDGE] ACCEPT script ({len(script)} B) → piping to {bash} stdin (no file footprint)")
            proc = subprocess.Popen([bash], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, text=False,
                                    env={"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": os.environ.get("HOME", "/root"),
                                         "TERM": "dumb", "LANG": "C.UTF-8"},
                                    preexec_fn=lambda: (os.setsid(), signal.signal(signal.SIGINT, signal.SIG_IGN)))
            writer.write(frame(1, json.dumps({"type": "LOG", "message": f"shell spawned pid={proc.pid}"}).encode()))
            await writer.drain()
            pump = asyncio.create_task(stream_pipe(proc.stdout, writer, "STDOUT"))
            proc.stdin.write(script.encode()); proc.stdin.close()
            code = await asyncio.get_running_loop().run_in_executor(None, proc.wait)
            await pump
            writer.write(frame(1, json.dumps({"type": "EXIT", "code": int(code)}).encode()))
            await writer.drain()
    except (asyncio.IncompleteReadError, ConnectionResetError, ValueError, OSError):
        pass
    finally:
        try: writer.close()
        except Exception: pass


async def main():
    srv = await asyncio.start_server(handle, HOST, PORT)
    print(f"[BRIDGE] Zero-trust WebSocket gateway bound to ws://{HOST}:{PORT}  (Ctrl+C to stop)")
    async with srv:
        await srv.serve_forever()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[BRIDGE] shutdown requested — closing gateway.")
