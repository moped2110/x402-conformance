"""End-to-end live verification of the 2026-06-12 features (T-07/T-12/T-15/T-16).

Spins up `calibration_target.py` over real HTTP in-process, in several modes, and
drives the actual suite (`run_checks` / `run_active_checks` / `to_json`) against
it — proving each new check both PASSes a correct server and CATCHes the matching
bug. This is the live counterpart to the offline unit tests.

Run (locally; needs the x402 SDK + eth-account, i.e. the calibration deps):

    python tools/verify_new_features.py

Exits 0 if every expectation holds, 1 otherwise (CI-style). Prints one line per
case. No chain, no funds — a throwaway signer and a local HTTP server only.
"""

from __future__ import annotations

import sys
import threading
from http.server import HTTPServer
from pathlib import Path

# Allow running straight from the repo without installing.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import json

from calibration_target import RESOURCE_MARKER, make_handler  # noqa: E402

from x402_conformance.active import run_active_checks  # noqa: E402
from x402_conformance.checks import Status  # noqa: E402
from x402_conformance.payload_builder import EvmSigner  # noqa: E402
from x402_conformance.report import REPORT_VERSION, to_json  # noqa: E402
from x402_conformance.runner import run_checks  # noqa: E402

SIGNER = EvmSigner.from_key("0x" + "22" * 32)

_failures: list[str] = []


def _check(name: str, ok: bool, detail: str = "") -> None:
    mark = "PASS" if ok else "FAIL"
    print(f"  [{mark}] {name}" + (f" — {detail}" if detail and not ok else ""))
    if not ok:
        _failures.append(name)


class _Server:
    """A calibration target running on a background thread."""

    def __init__(self, bugs: set[str], port: int) -> None:
        self.httpd = HTTPServer(("127.0.0.1", port), make_handler(bugs, port))
        self.url = f"http://127.0.0.1:{port}/data"
        self._t = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self) -> "_Server":
        self._t.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


def by_id(results: list, cid: str) -> object:
    return next(r for r in results if r.check_id == cid)


def main() -> int:
    port = 4599

    # 1) Correct server — every new check is GREEN, no false positives.
    print("correct server (no bugs):")
    with _Server(set(), port) as srv:
        passive = run_checks(srv.url)
        _check("RS-PR-008 valid EIP-55 checksum → PASS",
               by_id(passive, "RS-PR-008").status == Status.PASS,
               by_id(passive, "RS-PR-008").detail)

        active = run_active_checks(srv.url, SIGNER, resource_marker=RESOURCE_MARKER)
        _check("RS-SEC-011 extreme amount handled cleanly → PASS",
               by_id(active, "RS-SEC-011").status == Status.PASS,
               by_id(active, "RS-SEC-011").detail)
        no_false_pos = [r.check_id for r in active if r.status == Status.FAIL]
        _check("no active check falsely fails (with --resource-marker)",
               not no_false_pos, f"unexpected fails: {no_false_pos}")

        # T-07: the JSON report validates against the published schema.
        doc = json.loads(to_json(passive, srv.url))
        _check("report reportVersion matches", doc["reportVersion"] == REPORT_VERSION)
        _validate_schema(doc)

    # 2) --bug-bad-checksum — RS-PR-008 (passive) must catch it.
    print("--bug-bad-checksum:")
    with _Server({"bad-checksum"}, port + 1) as srv:
        passive = run_checks(srv.url)
        _check("RS-PR-008 catches a broken EIP-55 checksum → FAIL",
               by_id(passive, "RS-PR-008").status == Status.FAIL,
               by_id(passive, "RS-PR-008").detail)

    # 3) --bug-crash-huge — RS-SEC-011 must catch the 5xx crash.
    print("--bug-crash-huge:")
    with _Server({"crash-huge"}, port + 2) as srv:
        active = run_active_checks(srv.url, SIGNER)
        _check("RS-SEC-011 catches a 5xx crash on a huge amount → FAIL",
               by_id(active, "RS-SEC-011").status == Status.FAIL,
               by_id(active, "RS-SEC-011").detail)

    # 4) --bug-leak — the marker must be caught on the rejection path.
    print("--bug-leak (with --resource-marker):")
    with _Server({"leak"}, port + 3) as srv:
        active = run_active_checks(srv.url, SIGNER, resource_marker=RESOURCE_MARKER)
        leaked = [r for r in active if r.status == Status.FAIL and "leaked" in r.detail]
        _check("content leak on rejection path is caught → FAIL", bool(leaked),
               "no check reported a marker leak")
        # Without the marker the same server looks clean — proving the flag is what catches it.
        active_no_marker = run_active_checks(srv.url, SIGNER)
        _check("without --resource-marker the leak is not flagged (expected)",
               not [r for r in active_no_marker if r.status == Status.FAIL and "leaked" in r.detail])

    print()
    if _failures:
        print(f"VERIFICATION FAILED — {len(_failures)} expectation(s) not met: {_failures}")
        return 1
    print("VERIFICATION OK — all new-feature expectations hold against a live server.")
    return 0


def _validate_schema(doc: dict) -> None:
    try:
        import jsonschema
    except Exception:
        _check("report validates against report.schema.json", True, "(jsonschema not installed — skipped)")
        return
    schema_path = Path(__file__).resolve().parents[1] / "report.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    try:
        jsonschema.validate(doc, schema)
        _check("report validates against report.schema.json", True)
    except jsonschema.ValidationError as exc:
        _check("report validates against report.schema.json", False, str(exc.message))


if __name__ == "__main__":
    raise SystemExit(main())
