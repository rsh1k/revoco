"""Gate an MCP server that speaks over stdio, on recoverability.

Transport shape, which the MCP spec makes easy: stdio servers are launched as a
subprocess by the client and configured through environment variables, so a
proxy slots in by *becoming* the subprocess the client launches and launching
the real server itself.

    MCP client (agent host)
        | stdin/stdout — talks to this proxy as if it were the server
        v
    revoco stdio proxy        <- this module
        | stdin/stdout — spawns the real server as a subprocess
        v
    upstream MCP server

What makes this different from an allow/deny proxy
--------------------------------------------------
revoco splits authorization from execution on purpose: ``authorize`` plans the
undo and journals it against prior state, and ``confirm`` records that the
action actually happened. A proxy that only forwarded would throw the second
half away, and the undo plan would never bind the arguments you can only learn
from the response — the payment id, the created resource's identifier.

So this proxy correlates JSON-RPC ids. A gated ``tools/call`` holds its verdict
until upstream answers, then confirms on a result or abandons on an error. An
action that failed upstream must not leave a live undo plan behind claiming it
can reverse something that never happened.

What is gated
-------------
Only ``tools/call``. The handshake, ``initialize`` and discovery are not actions
and gating them would break the session for no benefit.

Limits, stated rather than discovered
-------------------------------------
* A ``tools/call`` without an ``id`` cannot be correlated to a response, so it
  cannot be confirmed. It is refused rather than forwarded unconfirmable.
* Line-delimited JSON only, one message per line, which is what the stdio
  transport specifies. No batching.
* Upstream stderr is passed through to the operator untouched.
"""

from __future__ import annotations

import json
import logging
import subprocess
import sys
import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import IO, Any

from ..controlplane import ControlPlane, Verdict

log = logging.getLogger("revoco.mcp")

GATED_METHOD = "tools/call"

# JSON-RPC reserved range ends at -32000; application errors live above it.
ERR_DENIED = -32001
ERR_UNCONFIRMABLE = -32002


@dataclass(frozen=True)
class Caller:
    """Who the proxy authorizes as.

    stdio has no client-to-server authentication, so identity cannot be derived
    from the transport. It is configured when the proxy is launched, and the
    delegation it names is what bounds the session — which is the honest place
    for it, because a token read from the environment proves only that whoever
    launched the process could read the environment.
    """

    actor_id: str
    actor_private_key: Any
    delegation_id: str
    session_id: str = "mcp-stdio"


class McpProxy:
    """A stdio MCP proxy that authorizes tool calls through a ControlPlane."""

    def __init__(
        self,
        control_plane: ControlPlane,
        caller: Caller,
        upstream_cmd: list[str],
        *,
        action_of: Callable[[str, dict[str, Any]], str] | None = None,
        risk_of: Callable[[str, dict[str, Any]], int] | None = None,
    ) -> None:
        if not upstream_cmd:
            raise ValueError("upstream_cmd is required: there is nothing to proxy to")
        self.cp = control_plane
        self.caller = caller
        self.upstream_cmd = upstream_cmd
        # MCP does not say whether a tool reads or writes, and guessing from the
        # name is how `invoices.approve` gets treated as a read. The caller
        # supplies the mapping or everything is a write, which is the safe default.
        self.action_of = action_of or (lambda tool, args: "write")
        self.risk_of = risk_of or (lambda tool, args: 0)

        self._proc: subprocess.Popen[bytes] | None = None
        self._pending: dict[Any, Verdict] = {}
        # Tools whose calls were never answered, set at shutdown. Readable so a
        # supervisor can act on it rather than having to scrape the log.
        self.stranded: tuple[str, ...] = ()
        self._lock = threading.Lock()

    # -- lifecycle ----------------------------------------------------------
    def run(self) -> int:
        self._proc = subprocess.Popen(
            self.upstream_cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=sys.stderr,
        )
        assert self._proc.stdin and self._proc.stdout
        pump = threading.Thread(target=self._pump_upstream, daemon=True)
        pump.start()
        try:
            for raw in sys.stdin.buffer:
                line = raw.decode("utf-8", errors="replace").strip()
                if line:
                    self._on_client_line(line, self._proc.stdin)
        except KeyboardInterrupt:
            pass
        finally:
            self._shutdown()
        return self._proc.returncode or 0

    def _shutdown(self) -> None:
        if self._proc is None:
            return
        try:
            if self._proc.stdin:
                self._proc.stdin.close()
        except OSError:
            pass

        # A pending call is one that was authorized, forwarded, and never
        # answered. Its journal entry is still PLANNED, so there is no undo path
        # to lose by closing it — but there is no basis for saying the action did
        # not happen either. The response may simply have gone with the session,
        # and the tool may have done exactly what it was asked to.
        #
        # So this is the one outcome the proxy cannot resolve, and the only
        # correct response is to say so loudly. An action that may have landed
        # with no undo recorded against it is precisely what an operator has to
        # be told, and it is invisible in a journal that merely shows an
        # abandoned entry.
        with self._lock:
            stranded, self._pending = list(self._pending.values()), {}
        self.stranded = tuple(v.tool for v in stranded)
        for verdict in stranded:
            self._abandon(
                verdict,
                "session ended before upstream answered; the outcome of this call "
                "is unknown and it may have taken effect",
            )
        if stranded:
            log.warning(
                "session ended with %d call(s) unanswered: %s. Each was authorized "
                "and forwarded, and whether it took effect is unknown. If it did, "
                "no undo was recorded for it.",
                len(stranded), ", ".join(sorted(self.stranded)),
            )

        try:
            self._proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self._proc.kill()
            # Reap it. A killed child that is never waited on stays a zombie for
            # as long as this process lives, which for a long-running proxy host
            # is the rest of the day.
            self._proc.wait()

    # -- client -> upstream -------------------------------------------------
    def _on_client_line(self, line: str, upstream: IO[bytes]) -> None:
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            log.error("dropping a line from the client that is not JSON")
            return

        if not isinstance(message, dict) or message.get("method") != GATED_METHOD:
            self._write(upstream, message)
            return

        request_id = message.get("id")
        params = message.get("params") or {}
        tool = params.get("name", "")
        args = params.get("arguments") or {}

        if request_id is None:
            # No id means no response to correlate, so `confirm` could never run
            # and the undo plan would never bind its result-derived arguments.
            # Forwarding it would be quietly giving up the half of the design
            # that makes the journal true.
            self._reply(self._error(
                None, ERR_UNCONFIRMABLE,
                f"{tool}: a tools/call without an id cannot be confirmed, so its "
                "undo plan could never be completed. Refused.",
            ))
            return

        verdict = self.cp.authorize(
            actor_private_key=self.caller.actor_private_key,
            actor_id=self.caller.actor_id,
            delegation_id=self.caller.delegation_id,
            tool=tool,
            args=args,
            action=self.action_of(tool, args),
            risk=self.risk_of(tool, args),
            session_id=self.caller.session_id,
        )

        if not verdict.allowed:
            self._reply(self._error(request_id, ERR_DENIED, self._why(verdict)))
            return

        # `effective_args` carries whatever redaction the gate applied, so the
        # upstream sees what policy permitted rather than what was asked for.
        forwarded = dict(message)
        forwarded["params"] = {**params, "arguments": verdict.effective_args or args}

        with self._lock:
            self._pending[request_id] = verdict
        self._write(upstream, forwarded)

    # -- upstream -> client -------------------------------------------------
    def _pump_upstream(self) -> None:
        assert self._proc and self._proc.stdout
        for raw in self._proc.stdout:
            line = raw.decode("utf-8", errors="replace").strip()
            if line:
                self._on_upstream_line(line)
            sys.stdout.buffer.write(raw)
            sys.stdout.buffer.flush()

    def _on_upstream_line(self, line: str) -> None:
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            return
        if not isinstance(message, dict) or "id" not in message:
            return
        with self._lock:
            verdict = self._pending.pop(message["id"], None)
        if verdict is None:
            return

        if "error" in message:
            # The action did not happen, so there is nothing to undo. An undo
            # plan left open here would be a rollback offered for a call that
            # never landed.
            self._abandon(verdict, f"upstream returned an error: {message['error']}")
            return
        self.cp.confirm(verdict, result=message.get("result"))

    # -- helpers ------------------------------------------------------------
    def _abandon(self, verdict: Verdict, reason: str) -> None:
        if verdict.journal_id is None:
            return
        try:
            self.cp.reversal.abandon(verdict.journal_id, reason)
        except Exception:
            log.exception("could not abandon journal entry %s", verdict.journal_id)

    @staticmethod
    def _why(verdict: Verdict) -> str:
        """A refusal a person can act on: which stage, and how recoverable."""
        return (
            f"{verdict.tool}: {verdict.reason} "
            f"[stage={verdict.stage}, reversibility={verdict.reversibility.value}]"
        )

    @staticmethod
    def _error(request_id: Any, code: int, message: str) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": request_id,
                "error": {"code": code, "message": message}}

    @staticmethod
    def _write(stream: IO[bytes], obj: Any) -> None:
        stream.write((json.dumps(obj, separators=(",", ":")) + "\n").encode())
        stream.flush()

    def _reply(self, obj: Any) -> None:
        self._write(sys.stdout.buffer, obj)
