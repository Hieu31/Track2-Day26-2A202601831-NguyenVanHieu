"""kit/isolation/child_driver.py — the process CONTRACTS.md 12 shows being
exec'd inside the sandbox::

    sandbox-exec -f duel.sb python3.12 -m kit.isolation.child_driver

Two independent jobs live here, selected by CLI flag:

``--probe``
    The hostile self-test CONTRACTS.md 12 describes: attempt every escape
    vector codex named — ``open``/``os.open``/``ctypes`` reads of the
    rival's sealed submissions and the corpus's ``truth.json``, a
    ``subprocess`` read of a run log, an outbound socket connect, and a
    write outside the duel's scratch copy — plus the *positive* control
    (read+write **inside** the scratch copy, which must keep working: a
    profile so broad it also blocks legitimate I/O would make
    ``probe_sandbox()`` "pass" for the wrong reason). Prints one JSON
    object to stdout and exits 0. This is the process
    :mod:`kit.isolation.sandbox`'s ``probe_sandbox()`` execs under
    ``sandbox-exec`` to measure the boundary for real, on this machine,
    every time — never a cached claim.

no flag / ``--serve`` (the actual duel path)
    Runs one team's artifact as a length-prefixed-JSON RPC server over
    stdin/stdout (:mod:`kit.isolation.rpc`): for each :class:`RpcRequest`
    read from stdin, reject it outright (an ``integrity`` record, kind
    ``malformed_decision``, per CONTRACTS.md 12.2 mechanic 2) unless its
    ``(server, tool)`` pair is in ``rpc.ALLOWED_METHODS``; otherwise hand
    it to ``--target module:callable`` (importlib-loaded) and write back
    whatever that callable decides. **``--target`` not loading is not a
    crash** — workspace hard rule 2 requires catching the ``ImportError``
    and degrading gracefully, so with no target (or one that fails to
    import — the student's ``agent/gateway.py`` may not exist yet while
    this file is read) the driver falls back to :func:`_default_target`,
    a conservative deny-everything policy. A target that raises on a
    given request degrades the same way, per-request, rather than taking
    the whole child down: one bad decision must not crash the process
    that is supposed to keep recording what happened next.

Stdlib only. No network as a *client* of anything (the ``--probe`` socket
attempt is the one exception, and it is expected to fail). No randomness,
no wall-clock.
"""

from __future__ import annotations

import argparse
import ctypes
import importlib
import io
import json
import logging
import os
import socket
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Callable, Mapping

from kit.isolation.rpc import (
    ALLOWED_METHODS,
    IntegrityKind,
    MethodNotAllowed,
    RpcFramingError,
    RpcRequest,
    RpcResponse,
    check_method,
    make_integrity,
    read_frame,
    reject,
    write_frame,
)

__all__ = [
    "SUBMISSIONS_FILE",
    "CORPUS_FILE",
    "RUNS_FILE",
    "EXPECTED_DENIED",
    "setup_probe_fixture",
    "run_probe_vectors",
    "load_target",
    "serve",
    "main",
]

_LOG = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# --probe: the hostile self-test (CONTRACTS.md 12)
# ---------------------------------------------------------------------------

# The three real assets the profile (CONTRACTS.md 12.1) denies file-read* on,
# by name — kept here as the single source of truth so sandbox.py's fixture
# setup and this module's own probe targets can never drift apart.
SUBMISSIONS_FILE = "rival.txt"
CORPUS_FILE = "truth.json"
RUNS_FILE = "secret_run.jsonl"

#: vector name -> whether a HEALTHY sandbox denies it. True for every
#: escape attempt; False for the one positive control (I/O inside the
#: duel's own scratch copy, which must keep working).
EXPECTED_DENIED: dict[str, bool] = {
    "open_read_denied_path": True,
    "os_open_read_denied_path": True,
    "subprocess_cat_denied_path": True,
    "ctypes_open_denied_path": True,
    "socket_connect_denied": True,
    "write_outside_scratch": True,
    "read_write_inside_scratch": False,
}


def setup_probe_fixture(arena_root: Path, duel_scratch: Path) -> None:
    """Create the ``submissions/`` / ``corpus_snapshot/`` / ``runs/``
    subtrees under ``arena_root`` (each holding one marker file with real,
    identifiable content — "did the sandbox actually stop me reading the
    rival's deck", not "there was nothing there to read anyway") and the
    ``duel_scratch`` directory the profile allows writes into."""
    arena_root = Path(arena_root)
    duel_scratch = Path(duel_scratch)

    submissions = arena_root / "submissions"
    corpus = arena_root / "corpus_snapshot"
    runs = arena_root / "runs"
    for d in (submissions, corpus, runs, duel_scratch):
        d.mkdir(parents=True, exist_ok=True)

    (submissions / SUBMISSIONS_FILE).write_text(
        "SEALED: the rival team's deck.json — this line must never be read by the other side.\n",
        encoding="utf-8",
    )
    (corpus / CORPUS_FILE).write_text(
        '{"secret": "truth.json must never leak to student code — CONTRACTS.md 2 invariant 4"}\n',
        encoding="utf-8",
    )
    (runs / RUNS_FILE).write_text(
        '{"secret_trace": "an opponent trace this side has not been handed yet"}\n',
        encoding="utf-8",
    )


def _probe_open_read(path: Path) -> dict:
    try:
        with open(path, "rb") as f:
            f.read()
        return {"denied": False, "detail": "open()/read() succeeded", "kind": None}
    except PermissionError as exc:
        return {"denied": True, "detail": f"PermissionError: {exc}", "kind": IntegrityKind.FS_ESCAPE.value}
    except OSError as exc:
        return {"denied": False, "detail": f"unexpected {type(exc).__name__}: {exc}", "kind": None}


def _probe_os_open_read(path: Path) -> dict:
    try:
        fd = os.open(str(path), os.O_RDONLY)
        try:
            os.read(fd, 4096)
        finally:
            os.close(fd)
        return {"denied": False, "detail": "os.open()/os.read() succeeded", "kind": None}
    except PermissionError as exc:
        return {"denied": True, "detail": f"PermissionError: {exc}", "kind": IntegrityKind.FS_ESCAPE.value}
    except OSError as exc:
        return {"denied": False, "detail": f"unexpected {type(exc).__name__}: {exc}", "kind": None}


def _probe_subprocess_cat(path: Path) -> dict:
    try:
        cp = subprocess.run(["/bin/cat", str(path)], capture_output=True, timeout=10)
    except Exception as exc:  # subprocess itself could be denied outright
        return {"denied": True, "detail": f"{type(exc).__name__}: {exc}", "kind": IntegrityKind.PROC_DENIED.value}
    if cp.returncode != 0:
        stderr = cp.stderr.decode("utf-8", "replace").strip()
        return {
            "denied": True,
            "detail": f"rc={cp.returncode} stderr={stderr!r}",
            "kind": IntegrityKind.PROC_DENIED.value,
        }
    return {"denied": False, "detail": f"rc=0 stdout={cp.stdout!r}", "kind": None}


def _probe_ctypes_open(path: Path) -> dict:
    try:
        import ctypes.util
        libc_name = "libc.dylib" if sys.platform == "darwin" else (ctypes.util.find_library("c") or "libc.so.6")
        libc = ctypes.CDLL(libc_name)
        libc.open.restype = ctypes.c_int
        libc.open.argtypes = [ctypes.c_char_p, ctypes.c_int]
        fd = libc.open(str(path).encode("utf-8"), 0)
        if fd < 0:
            return {"denied": True, "detail": f"fd={fd}", "kind": IntegrityKind.FS_ESCAPE.value}
        os.close(fd)
        return {"denied": False, "detail": f"fd={fd} (opened via raw libc)", "kind": None}
    except OSError as exc:
        return {"denied": True, "detail": f"{type(exc).__name__}: {exc}", "kind": IntegrityKind.FS_ESCAPE.value}


def _probe_socket_connect() -> dict:
    try:
        s = socket.create_connection(("1.1.1.1", 53), timeout=5)
        s.close()
        return {"denied": False, "detail": "connected", "kind": None}
    except PermissionError as exc:
        return {"denied": True, "detail": f"PermissionError: {exc}", "kind": IntegrityKind.NET_DENIED.value}
    except OSError as exc:
        # A machine with no route to 1.1.1.1 at all (offline CI) can raise a
        # DIFFERENT OSError than the sandbox's PermissionError. That does not
        # prove the SANDBOX blocked anything, so it is reported, not counted
        # as a pass — sandbox.py treats this vector's mismatch as advisory
        # rather than failing the whole probe over an unrelated network
        # condition (see sandbox.py's probe_sandbox() docstring).
        return {
            "denied": False,
            "detail": f"ambiguous {type(exc).__name__}: {exc} (not necessarily the sandbox — no route/offline also raises OSError)",
            "kind": None,
        }


def _probe_write_outside(path: Path) -> dict:
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write("pwned")
        return {"denied": False, "detail": "write succeeded", "kind": None}
    except PermissionError as exc:
        return {"denied": True, "detail": f"PermissionError: {exc}", "kind": IntegrityKind.FS_ESCAPE.value}
    except OSError as exc:
        return {"denied": False, "detail": f"unexpected {type(exc).__name__}: {exc}", "kind": None}


def _probe_read_write_inside(path: Path) -> dict:
    """The positive control: this MUST succeed. ``denied=True`` here means
    the profile is too broad — it is stopping the duel's own agent from
    working, not just stopping an escape."""
    try:
        path.write_text("ok", encoding="utf-8")
        readback = path.read_text(encoding="utf-8")
        if readback == "ok":
            return {"denied": False, "detail": "read+write inside duel scratch round-tripped", "kind": None}
        return {
            "denied": True,
            "detail": f"round-trip corrupted: wrote 'ok', read back {readback!r}",
            "kind": IntegrityKind.FS_ESCAPE.value,
        }
    except OSError as exc:
        return {"denied": True, "detail": f"{type(exc).__name__}: {exc}", "kind": IntegrityKind.FS_ESCAPE.value}


def run_probe_vectors(arena_root: Path, duel_scratch: Path) -> dict[str, dict]:
    """Attempt every vector in :data:`EXPECTED_DENIED`, unconditionally —
    called both as the ``--probe`` CLI body (usually run *inside*
    ``sandbox-exec``) and directly in-process for an unsandboxed baseline
    (see ``tests/test_isolation.py``, which calls this with no confinement
    at all to prove the vectors are exercising something real: without a
    profile, the escape attempts must succeed, not fail for an unrelated
    reason)."""
    arena_root = Path(arena_root)
    duel_scratch = Path(duel_scratch)
    return {
        "open_read_denied_path": _probe_open_read(arena_root / "submissions" / SUBMISSIONS_FILE),
        "os_open_read_denied_path": _probe_os_open_read(arena_root / "corpus_snapshot" / CORPUS_FILE),
        "subprocess_cat_denied_path": _probe_subprocess_cat(arena_root / "runs" / RUNS_FILE),
        "ctypes_open_denied_path": _probe_ctypes_open(arena_root / "submissions" / SUBMISSIONS_FILE),
        "socket_connect_denied": _probe_socket_connect(),
        "write_outside_scratch": _probe_write_outside(arena_root / "pwned.txt"),
        "read_write_inside_scratch": _probe_read_write_inside(duel_scratch / "ok.txt"),
    }


# ---------------------------------------------------------------------------
# serve: the actual duel RPC loop
# ---------------------------------------------------------------------------


def _default_target(request: RpcRequest) -> dict:
    """No ``--target`` artifact loaded (none given, or it failed to
    import). Conservative default: deny everything. CONTRACTS.md 4.1 makes
    a real ``deny`` free (0 credits charged) — refusing is always a safe
    fallback, never a silent success."""
    return {
        "verdict": "deny",
        "reason": f"no target artifact loaded; child_driver's default policy denies every call ({request.server}.{request.tool})",
    }


def load_target(spec: str) -> Callable[[RpcRequest], Mapping[str, object]] | None:
    """Resolve ``"module.path:attr[.attr...]"`` to a callable via
    :mod:`importlib`. Returns ``None`` (never raises) on any failure —
    malformed spec, missing module, missing attribute, or a resolved
    object that is not callable — logging why, per workspace hard rule 2:
    a collaborator's artifact "may not exist yet"; this driver must run
    without it."""
    module_name, sep, attr_path = spec.partition(":")
    if not sep or not module_name or not attr_path:
        _LOG.warning("malformed --target %r (want 'module.path:attr'); falling back to the default policy", spec)
        return None
    try:
        obj: object = importlib.import_module(module_name)
        for part in attr_path.split("."):
            obj = getattr(obj, part)
    except (ImportError, AttributeError) as exc:
        _LOG.warning(
            "--target %r not available yet (%s); falling back to the default deny-everything policy", spec, exc
        )
        return None
    if not callable(obj):
        _LOG.warning("--target %r resolved to a non-callable %r; falling back to the default policy", spec, obj)
        return None
    return obj  # type: ignore[return-value]


def serve(
    instream: io.BufferedIOBase,
    outstream: io.BufferedIOBase,
    target: Callable[[RpcRequest], Mapping[str, object]] | None = None,
) -> int:
    """The RPC serve loop: read :class:`RpcRequest` frames from
    ``instream`` until a clean EOF, dispatch each, write one
    :class:`RpcResponse` frame per request to ``outstream``. Returns the
    number of requests served.

    A disallowed ``(server, tool)`` is rejected — ``rpc.reject()``'s
    ``malformed_decision`` integrity record — **without ever calling**
    ``target``: CONTRACTS.md 12.2 mechanic 2 is "rejected, not executed,"
    and this is the one place that promise is actually kept or broken.
    A ``target`` that raises degrades to a safe ``deny`` for that one
    request rather than taking the whole server down — the arena still
    needs the next 9 rounds' worth of frames answered."""
    served = 0
    while True:
        try:
            frame = read_frame(instream)
        except RpcFramingError as exc:
            print(f"child_driver: framing error on stdin, stopping the serve loop: {exc}", file=sys.stderr)
            break
        if frame is None:
            break

        req_id_for_error = frame.get("req_id") if isinstance(frame, dict) else None
        try:
            request = RpcRequest.from_dict(frame)
        except (KeyError, ValueError, TypeError) as exc:
            resp = RpcResponse(
                req_id=str(req_id_for_error) if req_id_for_error is not None else "unknown",
                ok=False,
                error=make_integrity(IntegrityKind.MALFORMED_DECISION, f"unparsable RPC request: {exc}"),
            )
            write_frame(outstream, resp.to_dict())
            served += 1
            continue

        server, tool = request.method()
        try:
            check_method(server, tool)
        except MethodNotAllowed:
            write_frame(outstream, reject(request.req_id, server, tool).to_dict())
            served += 1
            continue

        active_target = target if target is not None else _default_target
        try:
            result = dict(active_target(request))
        except Exception as exc:  # the artifact's own bug must not crash the driver
            result = {"verdict": "deny", "reason": f"target raised {type(exc).__name__}: {exc}"}

        write_frame(outstream, RpcResponse(req_id=request.req_id, ok=True, result=result).to_dict())
        served += 1
    return served


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _run_probe_cli(args: argparse.Namespace) -> int:
    if args.arena_root is not None and args.duel_scratch is not None:
        # The real (usually sandboxed) path: a trusted caller outside any
        # confinement — sandbox.py's probe_sandbox() — already ran
        # setup_probe_fixture() before exec'ing this process. Doing it AGAIN
        # from in here would be a real bug under sandbox-exec: submissions/,
        # corpus_snapshot/ and runs/ sit under arena_root, which is
        # deny-file-write* everywhere except duel_scratch, so a second
        # mkdir/write attempt from inside the sandbox fails with
        # PermissionError before a single escape vector is even attempted —
        # exactly the kind of self-inflicted failure a hostile-child self-test
        # must not produce.
        arena_root = Path(args.arena_root)
        duel_scratch = Path(args.duel_scratch)
        owns_tmp = False
    else:
        # Standalone demo path (unsandboxed): this process owns its own
        # throwaway fixture, so setting it up here is safe and necessary.
        tmp = Path(tempfile.mkdtemp(prefix="child-driver-probe-"))
        arena_root = tmp / "arena"
        duel_scratch = arena_root / "scratch" / "demo-duel"
        owns_tmp = True
        setup_probe_fixture(arena_root, duel_scratch)

    vectors = run_probe_vectors(arena_root, duel_scratch)
    # Only stdout carries the RPC/probe payload; nothing else may print to
    # stdout in --probe mode or the parent's json.loads(cp.stdout) breaks.
    print(json.dumps(vectors, sort_keys=True))

    if owns_tmp:
        import shutil

        shutil.rmtree(tmp, ignore_errors=True)
    return 0


def _run_serve_cli(args: argparse.Namespace) -> int:
    target = load_target(args.target) if args.target else None
    serve(sys.stdin.buffer, sys.stdout.buffer, target=target)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m kit.isolation.child_driver",
        description="The sandboxed child: --probe for the CONTRACTS.md 12 self-test, "
        "otherwise the RPC serve loop for one team's artifact.",
    )
    parser.add_argument("--probe", action="store_true", help="run the hostile escape-vector self-test and exit")
    parser.add_argument("--serve", action="store_true", help="explicit: run the RPC serve loop on stdin/stdout")
    parser.add_argument("--arena-root", default=None, help="--probe only: the arena root to attack")
    parser.add_argument("--duel-scratch", default=None, help="--probe only: the (writable) duel scratch dir")
    parser.add_argument(
        "--target", default=None, help="--serve only: 'module.path:callable' deciding each RpcRequest"
    )
    args = parser.parse_args(argv)

    if args.probe:
        return _run_probe_cli(args)
    if args.serve:
        return _run_serve_cli(args)

    # No mode flag at all: a short, non-blocking, in-process demo (never
    # read real stdin here — that would hang a bare invocation forever,
    # which is a poor "demonstrates it runs" default per workspace hard
    # rule 6).
    print("kit.isolation.child_driver: no --probe or --serve given; running the in-process demo.\n", file=sys.stderr)
    demo_in, demo_out = io.BytesIO(), io.BytesIO()
    sample = sorted(ALLOWED_METHODS)[0] if ALLOWED_METHODS else ("slides", "query")
    from kit.isolation.rpc import write_frame as _wf

    _wf(demo_in, RpcRequest(req_id="req:demo-allowed", server=sample[0], tool=sample[1], args={}).to_dict())
    _wf(demo_in, RpcRequest(req_id="req:demo-denied", server="evil", tool="exec_shell", args={}).to_dict())
    demo_in.seek(0)
    served = serve(demo_in, demo_out)
    demo_out.seek(0)
    print(f"served {served} demo requests:", file=sys.stderr)
    while (frame := read_frame(demo_out)) is not None:
        print(f"  {frame}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
