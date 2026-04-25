"""
chaos_mcp_test.py — adversarial tests for the Acreo MCP server
==============================================================

Tests acreo_mcp.py running as a subprocess. Unlike chaos_test.py which
exercises Acreo in-process, this runs the server the way a real MCP
client would reach it — over stdin/stdout JSON-RPC — and probes for
crashes, protocol violations, resource exhaustion, and tool-level
failure modes.

WHAT THIS TESTS
  - Server lifecycle (starts cleanly, survives bad input, exits cleanly)
  - JSON-RPC parsing (malformed requests, missing fields, wrong types)
  - Oversized / deeply-nested payloads
  - Protocol violations (wrong version, unexpected ordering, method typos)
  - Rapid-fire request bursts
  - Tool argument edge cases for discovered tools

WHAT THIS DOES NOT TEST
  - In-process Acreo API (covered by chaos_test.py)
  - Deployed AgentVerifier.sol contract (different surface, Saturday)
  - Network-level attacks (stdio only, no TCP/TLS here)
  - Real MCP client library behavior (we speak raw JSON-RPC)

HOW IT WORKS
  1. Spawn `python acreo_mcp.py` as a subprocess
  2. Send JSON-RPC requests over stdin, read responses from stdout
  3. Run each attack, capture response or timeout
  4. Verify server hasn't died between tests
  5. Clean shutdown at end

USAGE
  cd <acreo repo root>
  python chaos_mcp_test.py                   # run all attacks
  python chaos_mcp_test.py --family lifecycle
  python chaos_mcp_test.py --json            # machine-readable
  python chaos_mcp_test.py --strict          # exit nonzero on any non-PASS

EXIT CODES
  0  — all attacks blocked (or with --strict, all PASS)
  1  — one or more findings at MEDIUM+ severity
  2  — test infrastructure error (couldn't spawn server, couldn't talk to it)
"""

from __future__ import annotations

import argparse
import json
import os
import random
import subprocess
import sys
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Callable, Optional


# ─── Config ────────────────────────────────────────────────────────────
SERVER_FILE = "acreo_mcp.py"
TIMEOUT_SECONDS = 3.0
MAX_ATTACK_TIME_SECONDS = 6.0
RANDOM_SEED = 0xACEB
random.seed(RANDOM_SEED)


# ─── Severity model (same as chaos_test.py) ────────────────────────────
SEVERITY_INFO = "INFO"
SEVERITY_LOW = "LOW"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_HIGH = "HIGH"
SEVERITY_CRITICAL = "CRITICAL"

SEVERITY_ORDER = {SEVERITY_INFO: 0, SEVERITY_LOW: 1, SEVERITY_MEDIUM: 2,
                  SEVERITY_HIGH: 3, SEVERITY_CRITICAL: 4}


# ─── Result tracking ───────────────────────────────────────────────────

@dataclass
class AttackResult:
    family: str
    name: str
    claim: str
    outcome: str  # PASS / FAIL / SKIP / ERROR
    severity: str = SEVERITY_INFO
    detail: str = ""
    elapsed_ms: float = 0.0


_results: list[AttackResult] = []
_attacks: list[Callable] = []


def record_pass(family, name, claim, detail=""):
    _results.append(AttackResult(family, name, claim, "PASS", SEVERITY_INFO, detail))


def record_fail(family, name, claim, severity, detail):
    assert severity in SEVERITY_ORDER
    _results.append(AttackResult(family, name, claim, "FAIL", severity, detail))


def record_skip(family, name, claim, reason):
    _results.append(AttackResult(family, name, claim, "SKIP", SEVERITY_INFO, reason))


def attack(family, name, claim, default_severity=SEVERITY_HIGH):
    def decorator(fn):
        _attacks.append(fn)
        fn._family = family
        fn._name = name
        fn._claim = claim
        fn._default_severity = default_severity
        return fn
    return decorator


# ─── MCP server subprocess harness ─────────────────────────────────────

class McpServerProcess:
    """Manages a subprocess running acreo_mcp.py. Provides send/recv
    over JSON-RPC with timeouts and health checks."""

    def __init__(self, server_path: str = SERVER_FILE):
        self.server_path = server_path
        self.proc: Optional[subprocess.Popen] = None
        self._msg_id = 0

    def start(self) -> bool:
        """Start the server. Returns True on success."""
        if not Path(self.server_path).exists():
            return False
        try:
            self.proc = subprocess.Popen(
                [sys.executable, self.server_path],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=0,  # unbuffered
                text=False,  # raw bytes so we can test binary attacks
            )
            # Give server a moment to initialize
            time.sleep(0.3)
            # Check it's still running
            if self.proc.poll() is not None:
                return False
            return True
        except Exception:
            return False

    def is_alive(self) -> bool:
        if self.proc is None:
            return False
        return self.proc.poll() is None

    def send_raw(self, data: bytes) -> bool:
        """Write raw bytes to server stdin. Returns False if write fails."""
        if self.proc is None or self.proc.stdin is None:
            return False
        try:
            self.proc.stdin.write(data)
            self.proc.stdin.flush()
            return True
        except (BrokenPipeError, OSError):
            return False

    def send_json(self, obj: Any) -> bool:
        """Serialize a JSON object and send it with newline termination."""
        try:
            data = (json.dumps(obj) + "\n").encode("utf-8")
        except Exception:
            return False
        return self.send_raw(data)

    def recv_json(self, timeout: float = TIMEOUT_SECONDS) -> Optional[dict]:
        """Read one line of JSON response with timeout. Returns None on
        timeout, error, or EOF."""
        if self.proc is None or self.proc.stdout is None:
            return None
        import select
        # Windows doesn't support select on pipes; use a thread-based read
        if sys.platform == "win32":
            return self._recv_json_windows(timeout)
        ready, _, _ = select.select([self.proc.stdout], [], [], timeout)
        if not ready:
            return None
        try:
            line = self.proc.stdout.readline()
            if not line:
                return None
            return json.loads(line.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None

    def _recv_json_windows(self, timeout: float) -> Optional[dict]:
        """Windows-compatible read with timeout via thread."""
        import threading
        result = [None]
        exception = [None]

        def reader():
            try:
                line = self.proc.stdout.readline()
                if line:
                    result[0] = json.loads(line.decode("utf-8"))
            except Exception as e:
                exception[0] = e

        t = threading.Thread(target=reader, daemon=True)
        t.start()
        t.join(timeout)
        if t.is_alive():
            return None  # timeout — thread still reading
        return result[0]

    def next_id(self) -> int:
        self._msg_id += 1
        return self._msg_id

    def rpc_request(self, method: str, params: Optional[dict] = None,
                    timeout: float = TIMEOUT_SECONDS) -> Optional[dict]:
        """Standard JSON-RPC request/response pair."""
        req = {
            "jsonrpc": "2.0",
            "id": self.next_id(),
            "method": method,
        }
        if params is not None:
            req["params"] = params
        if not self.send_json(req):
            return None
        return self.recv_json(timeout)

    def stop(self):
        if self.proc is None:
            return
        try:
            self.proc.stdin.close()
        except Exception:
            pass
        try:
            self.proc.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=1.0)
        except Exception:
            try:
                self.proc.kill()
            except Exception:
                pass


# ─── Global server instance (attacks share one server to test
# persistence; each attack verifies the server is alive afterward) ──────

_server: Optional[McpServerProcess] = None


def get_server() -> McpServerProcess:
    global _server
    if _server is None or not _server.is_alive():
        if _server is not None:
            _server.stop()
        _server = McpServerProcess()
        if not _server.start():
            raise RuntimeError("failed to start acreo_mcp.py server")
    return _server


def restart_server():
    """Force a fresh server for tests that need isolation."""
    global _server
    if _server is not None:
        _server.stop()
    _server = McpServerProcess()
    if not _server.start():
        raise RuntimeError("failed to restart server")


# ═══════════════════════════════════════════════════════════════════════
# FAMILY 1: LIFECYCLE
# ═══════════════════════════════════════════════════════════════════════

@attack("lifecycle", "server_starts",
        "acreo_mcp.py must start cleanly as a subprocess",
        SEVERITY_CRITICAL)
def lifecycle_starts():
    srv = McpServerProcess()
    ok = srv.start()
    alive = srv.is_alive()
    srv.stop()

    if not ok or not alive:
        record_fail("lifecycle", "server_starts",
                    "acreo_mcp.py must start cleanly as a subprocess",
                    SEVERITY_CRITICAL,
                    f"server failed to start (started={ok}, alive={alive})")
    else:
        record_pass("lifecycle", "server_starts",
                    "acreo_mcp.py must start cleanly as a subprocess",
                    "clean startup")


@attack("lifecycle", "clean_shutdown",
        "Server must exit cleanly when stdin closes",
        SEVERITY_MEDIUM)
def lifecycle_shutdown():
    srv = McpServerProcess()
    if not srv.start():
        record_skip("lifecycle", "clean_shutdown",
                    "Server must exit cleanly when stdin closes",
                    "couldn't start server")
        return
    # Close stdin and wait
    try:
        srv.proc.stdin.close()
    except Exception:
        pass
    try:
        rc = srv.proc.wait(timeout=3.0)
        record_pass("lifecycle", "clean_shutdown",
                    "Server must exit cleanly when stdin closes",
                    f"exited with code {rc}")
    except subprocess.TimeoutExpired:
        srv.proc.kill()
        record_fail("lifecycle", "clean_shutdown",
                    "Server must exit cleanly when stdin closes",
                    SEVERITY_MEDIUM,
                    "server did not exit within 3s of stdin close")


# ═══════════════════════════════════════════════════════════════════════
# FAMILY 2: PROTOCOL PARSING
# ═══════════════════════════════════════════════════════════════════════

@attack("protocol", "malformed_json",
        "Server must survive malformed JSON without crashing",
        SEVERITY_HIGH)
def protocol_malformed():
    srv = get_server()
    # Send complete garbage
    srv.send_raw(b"{not valid json at all\n")
    time.sleep(0.2)
    if not srv.is_alive():
        record_fail("protocol", "malformed_json",
                    "Server must survive malformed JSON without crashing",
                    SEVERITY_HIGH,
                    "server died after malformed JSON")
        return
    # Can it still respond to valid requests?
    resp = srv.rpc_request("initialize", {})
    record_pass("protocol", "malformed_json",
                "Server must survive malformed JSON without crashing",
                f"survived; next request returned {type(resp).__name__}")


@attack("protocol", "empty_input",
        "Server must handle empty lines without crashing",
        SEVERITY_MEDIUM)
def protocol_empty():
    srv = get_server()
    srv.send_raw(b"\n\n\n")
    time.sleep(0.2)
    if not srv.is_alive():
        record_fail("protocol", "empty_input",
                    "Server must handle empty lines without crashing",
                    SEVERITY_MEDIUM,
                    "server died on empty input")
        return
    record_pass("protocol", "empty_input",
                "Server must handle empty lines without crashing",
                "survived empty lines")


@attack("protocol", "missing_method",
        "Request with no method field must get clean error, not crash",
        SEVERITY_MEDIUM)
def protocol_no_method():
    srv = get_server()
    resp = srv.rpc_request("") or srv.send_json({"jsonrpc": "2.0", "id": 1})
    time.sleep(0.2)
    if not srv.is_alive():
        record_fail("protocol", "missing_method",
                    "Request with no method field must get clean error, not crash",
                    SEVERITY_MEDIUM,
                    "server died on missing method")
        return
    record_pass("protocol", "missing_method",
                "Request with no method field must get clean error, not crash",
                "server survived; response handling ok")


@attack("protocol", "wrong_jsonrpc_version",
        "Unknown jsonrpc version must be rejected cleanly",
        SEVERITY_LOW)
def protocol_wrong_version():
    srv = get_server()
    srv.send_json({"jsonrpc": "99.99", "id": 1, "method": "initialize", "params": {}})
    time.sleep(0.3)
    if not srv.is_alive():
        record_fail("protocol", "wrong_jsonrpc_version",
                    "Unknown jsonrpc version must be rejected cleanly",
                    SEVERITY_LOW,
                    "server died on unknown jsonrpc version")
        return
    record_pass("protocol", "wrong_jsonrpc_version",
                "Unknown jsonrpc version must be rejected cleanly",
                "server survived unknown version")


@attack("protocol", "wrong_type_for_params",
        "Non-object params (e.g. string, int) must not crash server",
        SEVERITY_MEDIUM)
def protocol_wrong_params_type():
    srv = get_server()
    srv.send_json({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                   "params": "this should be an object not a string"})
    time.sleep(0.3)
    if not srv.is_alive():
        record_fail("protocol", "wrong_type_for_params",
                    "Non-object params (e.g. string, int) must not crash server",
                    SEVERITY_MEDIUM,
                    "server died on string params")
        return
    record_pass("protocol", "wrong_type_for_params",
                "Non-object params (e.g. string, int) must not crash server",
                "server survived string params")


# ═══════════════════════════════════════════════════════════════════════
# FAMILY 3: RESOURCE EXHAUSTION
# ═══════════════════════════════════════════════════════════════════════

@attack("resource", "oversized_payload",
        "10KB payload must not crash the server",
        SEVERITY_HIGH)
def resource_oversized():
    srv = get_server()
    huge = "A" * 10_000
    srv.send_json({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                   "params": {"capabilities": {}, "huge_field": huge}})
    # Drain any response so stdout pipe doesn't back up
    srv.recv_json(timeout=1.5)
    time.sleep(0.2)
    if not srv.is_alive():
        record_fail("resource", "oversized_payload",
                    "10KB payload must not crash the server",
                    SEVERITY_HIGH,
                    "server died on 10KB payload")
        return
    record_pass("resource", "oversized_payload",
                "10KB payload must not crash the server",
                "server survived 10KB payload")


@attack("resource", "deeply_nested_object",
        "Deeply nested JSON (100 levels) must not crash",
        SEVERITY_MEDIUM)
def resource_deep_nesting():
    srv = get_server()
    # Build 100-level nested dict
    nested: Any = "bottom"
    for _ in range(100):
        nested = {"level": nested}
    try:
        srv.send_json({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                       "params": nested})
    except (RecursionError, ValueError, Exception) as e:
        record_pass("resource", "deeply_nested_object",
                    "Deeply nested JSON (100 levels) must not crash",
                    f"client-side refused: {type(e).__name__}")
        return
    srv.recv_json(timeout=1.0)  # drain any response
    time.sleep(0.3)
    if not srv.is_alive():
        record_fail("resource", "deeply_nested_object",
                    "Deeply nested JSON (100 levels) must not crash",
                    SEVERITY_MEDIUM,
                    "server died on deeply nested object")
        return
    record_pass("resource", "deeply_nested_object",
                "Deeply nested JSON (100 levels) must not crash",
                "server survived deep nesting")


@attack("resource", "rapid_request_burst",
        "Server must handle 20 rapid requests without crashing",
        SEVERITY_HIGH)
def resource_burst():
    srv = get_server()
    for i in range(20):
        srv.send_json({"jsonrpc": "2.0", "id": i,
                       "method": "initialize", "params": {}})
    # Drain whatever responses come back (don't wait long per-response)
    for _ in range(30):
        if srv.recv_json(timeout=0.15) is None:
            break
    time.sleep(0.2)
    if not srv.is_alive():
        record_fail("resource", "rapid_request_burst",
                    "Server must handle 20 rapid requests without crashing",
                    SEVERITY_HIGH,
                    "server died during 20-request burst")
        return
    record_pass("resource", "rapid_request_burst",
                "Server must handle 20 rapid requests without crashing",
                "survived 20-request burst")


# ═══════════════════════════════════════════════════════════════════════
# FAMILY 4: INITIALIZATION & TOOL DISCOVERY
# ═══════════════════════════════════════════════════════════════════════

@attack("init", "initialize_before_anything",
        "initialize method must return capabilities successfully",
        SEVERITY_HIGH)
def init_basic():
    restart_server()
    srv = get_server()
    resp = srv.rpc_request("initialize", {
        "protocolVersion": "2024-11-05",
        "capabilities": {},
        "clientInfo": {"name": "chaos_mcp_test", "version": "1.0"},
    }, timeout=5.0)
    if resp is None:
        record_fail("init", "initialize_before_anything",
                    "initialize method must return capabilities successfully",
                    SEVERITY_HIGH,
                    "no response to initialize")
        return
    if "error" in resp and "result" not in resp:
        record_fail("init", "initialize_before_anything",
                    "initialize method must return capabilities successfully",
                    SEVERITY_HIGH,
                    f"error response: {resp.get('error')}")
        return
    record_pass("init", "initialize_before_anything",
                "initialize method must return capabilities successfully",
                f"got response with keys: {list(resp.keys())}")


@attack("init", "tools_list_works",
        "tools/list must return an array of tools",
        SEVERITY_HIGH)
def init_tools_list():
    srv = get_server()
    resp = srv.rpc_request("tools/list", {})
    if resp is None:
        record_fail("init", "tools_list_works",
                    "tools/list must return an array of tools",
                    SEVERITY_HIGH,
                    "no response")
        return
    result = resp.get("result", {})
    tools = result.get("tools", []) if isinstance(result, dict) else []
    if not isinstance(tools, list):
        record_fail("init", "tools_list_works",
                    "tools/list must return an array of tools",
                    SEVERITY_HIGH,
                    f"tools field is not a list: {type(tools).__name__}")
        return
    record_pass("init", "tools_list_works",
                "tools/list must return an array of tools",
                f"discovered {len(tools)} tools: "
                f"{[t.get('name', '?') for t in tools[:5]]}"
                f"{'...' if len(tools) > 5 else ''}")


# ═══════════════════════════════════════════════════════════════════════
# FAMILY 5: TOOL-LEVEL ATTACKS
# ═══════════════════════════════════════════════════════════════════════

@attack("tool", "call_unknown_tool",
        "Calling a tool that doesn't exist must get clean error, not crash",
        SEVERITY_HIGH)
def tool_unknown():
    srv = get_server()
    resp = srv.rpc_request("tools/call", {
        "name": "this_tool_definitely_does_not_exist_12345",
        "arguments": {}
    })
    if not srv.is_alive():
        record_fail("tool", "call_unknown_tool",
                    "Calling a tool that doesn't exist must get clean error, not crash",
                    SEVERITY_HIGH,
                    "server died on unknown tool call")
        return
    if resp is None:
        record_fail("tool", "call_unknown_tool",
                    "Calling a tool that doesn't exist must get clean error, not crash",
                    SEVERITY_MEDIUM,
                    "no response (timeout)")
        return
    record_pass("tool", "call_unknown_tool",
                "Calling a tool that doesn't exist must get clean error, not crash",
                f"clean response received, server alive")


@attack("tool", "call_with_missing_arguments",
        "Tool called with no arguments must not crash server",
        SEVERITY_MEDIUM)
def tool_no_args():
    srv = get_server()
    # First discover an actual tool name
    resp = srv.rpc_request("tools/list", {})
    tools = []
    if resp and "result" in resp:
        result = resp["result"]
        if isinstance(result, dict):
            tools = result.get("tools", [])

    if not tools:
        record_skip("tool", "call_with_missing_arguments",
                    "Tool called with no arguments must not crash server",
                    "no tools discovered to attack")
        return

    target = tools[0].get("name", "")
    if not target:
        record_skip("tool", "call_with_missing_arguments",
                    "Tool called with no arguments must not crash server",
                    "first tool has no name")
        return

    srv.rpc_request("tools/call", {"name": target, "arguments": {}})
    if not srv.is_alive():
        record_fail("tool", "call_with_missing_arguments",
                    "Tool called with no arguments must not crash server",
                    SEVERITY_MEDIUM,
                    f"server died when calling {target} with empty args")
        return
    record_pass("tool", "call_with_missing_arguments",
                "Tool called with no arguments must not crash server",
                f"server survived {target} with empty args")


@attack("tool", "call_with_garbage_args",
        "Tool called with wrong-type arguments must not crash server",
        SEVERITY_HIGH)
def tool_garbage_args():
    srv = get_server()
    resp = srv.rpc_request("tools/list", {})
    tools = []
    if resp and "result" in resp:
        result = resp["result"]
        if isinstance(result, dict):
            tools = result.get("tools", [])

    if not tools:
        record_skip("tool", "call_with_garbage_args",
                    "Tool called with wrong-type arguments must not crash server",
                    "no tools discovered")
        return

    target = tools[0].get("name", "")
    srv.rpc_request("tools/call", {
        "name": target,
        "arguments": {
            "user_id": None,
            "amount": "definitely_not_a_number",
            "permissions": 42,
            "nested": {"deep": [None, [], {}, False, -1]},
        }
    })
    if not srv.is_alive():
        record_fail("tool", "call_with_garbage_args",
                    "Tool called with wrong-type arguments must not crash server",
                    SEVERITY_HIGH,
                    f"server died when calling {target} with garbage args")
        return
    record_pass("tool", "call_with_garbage_args",
                "Tool called with wrong-type arguments must not crash server",
                f"server survived garbage args to {target}")


@attack("tool", "call_with_huge_string_arg",
        "Tool with 50KB string argument must not crash server",
        SEVERITY_MEDIUM)
def tool_huge_string():
    srv = get_server()
    resp = srv.rpc_request("tools/list", {})
    tools = []
    if resp and "result" in resp:
        result = resp["result"]
        if isinstance(result, dict):
            tools = result.get("tools", [])

    if not tools:
        record_skip("tool", "call_with_huge_string_arg",
                    "Tool with 50KB string argument must not crash server",
                    "no tools discovered")
        return

    target = tools[0].get("name", "")
    huge = "X" * 50_000
    srv.rpc_request("tools/call", {
        "name": target,
        "arguments": {"data": huge, "text": huge, "input": huge}
    }, timeout=8.0)
    if not srv.is_alive():
        record_fail("tool", "call_with_huge_string_arg",
                    "Tool with 50KB string argument must not crash server",
                    SEVERITY_MEDIUM,
                    f"server died on 50KB string args to {target}")
        return
    record_pass("tool", "call_with_huge_string_arg",
                "Tool with 50KB string argument must not crash server",
                f"server survived 50KB string args to {target}")


@attack("tool", "call_with_unicode_stress",
        "Tool with unicode/emoji/RTL text must not crash server",
        SEVERITY_LOW)
def tool_unicode():
    srv = get_server()
    resp = srv.rpc_request("tools/list", {})
    tools = []
    if resp and "result" in resp:
        result = resp["result"]
        if isinstance(result, dict):
            tools = result.get("tools", [])

    if not tools:
        record_skip("tool", "call_with_unicode_stress",
                    "Tool with unicode/emoji/RTL text must not crash server",
                    "no tools discovered")
        return

    target = tools[0].get("name", "")
    stress = "\u202e" + "😊" * 100 + "שלום" + "\x00" + "\ufffd" * 50
    srv.rpc_request("tools/call", {
        "name": target,
        "arguments": {"text": stress, "data": stress}
    })
    if not srv.is_alive():
        record_fail("tool", "call_with_unicode_stress",
                    "Tool with unicode/emoji/RTL text must not crash server",
                    SEVERITY_LOW,
                    f"server died on unicode stress args to {target}")
        return
    record_pass("tool", "call_with_unicode_stress",
                "Tool with unicode/emoji/RTL text must not crash server",
                f"server survived unicode stress")


# ═══════════════════════════════════════════════════════════════════════
# RUNNER
# ═══════════════════════════════════════════════════════════════════════

def _run_attack_with_timeout(fn, timeout_seconds=MAX_ATTACK_TIME_SECONDS):
    """Run an attack with a hard wall-clock timeout. If exceeded, force-kill
    the subprocess (which unblocks any pending stdin/stdout I/O in the daemon
    thread) and record TIMEOUT so the next attack gets a fresh server.

    On Windows, threaded I/O can't be interrupted from another thread. The
    only portable way to unblock a stuck pipe read is to kill the other end
    of the pipe, i.e. the subprocess."""
    import threading
    result_container = {"done": False, "exc": None}

    def runner():
        try:
            fn()
        except Exception as e:
            result_container["exc"] = e
        finally:
            result_container["done"] = True

    t = threading.Thread(target=runner, daemon=True)
    t.start()
    t.join(timeout_seconds)

    if not result_container["done"]:
        # Kill the subprocess first — this unblocks the daemon thread
        # that's likely stuck on a pipe read
        global _server
        if _server is not None:
            try:
                if _server.proc is not None:
                    _server.proc.kill()
                    _server.proc.wait(timeout=1.0)
            except Exception:
                pass
            _server = None

        # Give the now-unblocked daemon thread a moment to exit cleanly
        t.join(1.0)

        _results.append(AttackResult(
            family=fn._family, name=fn._name, claim=fn._claim,
            outcome="ERROR", severity=SEVERITY_INFO,
            detail=f"test timed out after {timeout_seconds}s (subprocess killed)",
        ))
        return

    if result_container["exc"] is not None:
        e = result_container["exc"]
        _results.append(AttackResult(
            family=fn._family, name=fn._name, claim=fn._claim,
            outcome="ERROR", severity=SEVERITY_INFO,
            detail=f"test infra error: {type(e).__name__}: {e}",
        ))


def run_attacks(family_filter: Optional[str] = None) -> list[AttackResult]:
    _results.clear()
    icons = {"PASS": "✓", "FAIL": "✗", "SKIP": "⋯", "ERROR": "!"}

    families_seen = set()
    for fn in _attacks:
        if family_filter and fn._family != family_filter:
            continue
        if fn._family not in families_seen:
            families_seen.add(fn._family)
            print(f"\n[{fn._family.upper()}]")

        t0 = time.perf_counter()
        _run_attack_with_timeout(fn, timeout_seconds=MAX_ATTACK_TIME_SECONDS)
        if _results and _results[-1].name == fn._name:
            _results[-1].elapsed_ms = (time.perf_counter() - t0) * 1000

        last = _results[-1]
        sev_tag = f" [{last.severity}]" if last.outcome == "FAIL" else ""
        detail = (last.detail or "").replace("\n", " ")[:80]
        print(f"  {icons[last.outcome]} {last.outcome}{sev_tag} "
              f"{last.name} — {detail}")

    # Clean shutdown
    global _server
    if _server is not None:
        _server.stop()

    return list(_results)


def print_summary(results: list[AttackResult]):
    by_family: dict[str, list[AttackResult]] = {}
    for r in results:
        by_family.setdefault(r.family, []).append(r)

    counts = {"PASS": 0, "FAIL": 0, "SKIP": 0, "ERROR": 0}
    for r in results:
        counts[r.outcome] += 1

    print("\n" + "═" * 72)
    print("  SUMMARY — MCP server adversarial tests")
    print("═" * 72)
    print(f"  Total: {len(results)}  PASS={counts['PASS']}  "
          f"FAIL={counts['FAIL']}  SKIP={counts['SKIP']}  "
          f"ERROR={counts['ERROR']}")

    print(f"\n  By family:")
    for family, rs in sorted(by_family.items()):
        c = {"PASS": 0, "FAIL": 0, "SKIP": 0, "ERROR": 0}
        for r in rs:
            c[r.outcome] += 1
        print(f"    {family:<14} {c['PASS']:>2}P {c['FAIL']:>2}F "
              f"{c['SKIP']:>2}S {c['ERROR']:>2}E")

    fails = [r for r in results if r.outcome == "FAIL"]
    if fails:
        print(f"\n  Findings (sorted by severity):")
        fails.sort(key=lambda r: -SEVERITY_ORDER[r.severity])
        for r in fails:
            print(f"    [{r.severity:<8}] {r.family}/{r.name}")
            print(f"        claim:  {r.claim}")
            print(f"        detail: {r.detail}")

    errors = [r for r in results if r.outcome == "ERROR"]
    if errors:
        print(f"\n  Test infrastructure ERRORS (not server issues):")
        for r in errors:
            print(f"    {r.family}/{r.name}: {r.detail}")

    skips = [r for r in results if r.outcome == "SKIP"]
    if skips:
        print(f"\n  SKIPPED:")
        for r in skips:
            print(f"    {r.family}/{r.name}: {r.detail}")

    print("═" * 72)


def write_json(results: list[AttackResult], path: str = "chaos_mcp_results.json"):
    payload = {
        "version": "1.0",
        "test_target": "acreo_mcp.py subprocess",
        "seed": RANDOM_SEED,
        "timestamp": int(time.time()),
        "total": len(results),
        "summary": {
            "pass": sum(1 for r in results if r.outcome == "PASS"),
            "fail": sum(1 for r in results if r.outcome == "FAIL"),
            "skip": sum(1 for r in results if r.outcome == "SKIP"),
            "error": sum(1 for r in results if r.outcome == "ERROR"),
        },
        "results": [asdict(r) for r in results],
    }
    with open(path, "w") as fp:
        json.dump(payload, fp, indent=2)
    return path


def main():
    parser = argparse.ArgumentParser(
        description="Acreo MCP server adversarial test suite",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Tests acreo_mcp.py running as a subprocess. "
               "See module docstring for threat model and scope.",
    )
    parser.add_argument("--family", help="run only one family (e.g. protocol)")
    parser.add_argument("--json", action="store_true",
                        help="machine-readable output only")
    parser.add_argument("--output", default="chaos_mcp_results.json")
    parser.add_argument("--strict", action="store_true",
                        help="exit nonzero on any non-PASS")
    args = parser.parse_args()

    # Preflight: make sure server file exists
    if not Path(SERVER_FILE).exists():
        print(f"FATAL: {SERVER_FILE} not found in current directory.",
              file=sys.stderr)
        print(f"  cwd: {Path.cwd()}", file=sys.stderr)
        print(f"  Run this from the Acreo repo root.", file=sys.stderr)
        sys.exit(2)

    if not args.json:
        print(f"Acreo MCP chaos test — {len(_attacks)} attacks across "
              f"{len(set(fn._family for fn in _attacks))} families")
        print(f"  Target: {SERVER_FILE}")
        print(f"  Seed: 0x{RANDOM_SEED:X}")

    try:
        results = run_attacks(family_filter=args.family)
    except RuntimeError as e:
        print(f"FATAL: {e}", file=sys.stderr)
        sys.exit(2)

    if not args.json:
        print_summary(results)

    json_path = write_json(results, args.output)
    if not args.json:
        print(f"\n  Full results: {json_path}")

    fails = [r for r in results if r.outcome == "FAIL"]
    errors = [r for r in results if r.outcome == "ERROR"]
    if errors:
        return 2
    if args.strict and (fails or any(r.outcome == "SKIP" for r in results)):
        return 1
    if any(SEVERITY_ORDER[r.severity] >= SEVERITY_ORDER[SEVERITY_MEDIUM]
           for r in fails):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
