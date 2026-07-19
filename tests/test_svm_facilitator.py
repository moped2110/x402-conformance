"""FA-SVM /verify checks against a conformant and a thin mock facilitator (K2-1 live group).

Two mock facilitators, no network:
- A *strict* one that verifies with our own ``verify_exact_svm_transaction`` — the FA-SVM
  matrix must go all-PASS against it (valid accepted, every tamper rejected).
- A *thin* one that returns ``isValid:true`` for everything, modelling the Kora x402
  demo facilitator. The valid case still passes, but every negative check FAILS — the
  finding (a signer-delegating facilitator does not structurally verify) as a test.

solders-only (builds real payloads); skips without it. Offline via httpx.MockTransport.
"""

from __future__ import annotations

import json
from collections.abc import Callable

import httpx
import pytest

pytest.importorskip("solders")

from x402_conformance.checks import CheckResult, Status
from x402_conformance.checks.svm_facilitator import (
    SvmFacilitatorContext,
    _load_payer_keypair_bytes,
    evaluate_svm_facilitator,
)
from x402_conformance.svm_verify import verify_exact_svm_transaction

FAC = "http://facilitator.example"


def _strict_handler(request: httpx.Request) -> httpx.Response:
    """A conformant facilitator: run our structural verifier over the submitted tx."""
    body = json.loads(request.content)
    reqs = body["paymentRequirements"]
    tx = body["paymentPayload"]["payload"]["transaction"]
    reason = verify_exact_svm_transaction(
        tx,
        mint=reqs["asset"],
        pay_to=reqs["payTo"],
        amount=int(reqs["amount"]),
        fee_payer=reqs["extra"]["feePayer"],
    )
    if reason is None:
        return httpx.Response(200, json={"isValid": True})
    return httpx.Response(200, json={"isValid": False, "invalidReason": reason})


def _thin_handler(request: httpx.Request) -> httpx.Response:
    """A thin verifier: accepts anything it can relay/sign (the Kora demo behaviour)."""
    return httpx.Response(200, json={"isValid": True})


def _absent_handler(request: httpx.Request) -> httpx.Response:
    return httpx.Response(404, text="not found")


def _context(handler: Callable[[httpx.Request], httpx.Response]) -> SvmFacilitatorContext:
    from solders.hash import Hash
    from solders.keypair import Keypair

    payer = Keypair()
    client = httpx.Client(transport=httpx.MockTransport(handler))
    return SvmFacilitatorContext(
        base_url=FAC,
        client=client,
        network="solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
        asset=str(Keypair().pubkey()),
        decimals=6,
        pay_to=str(Keypair().pubkey()),
        amount=1000,
        fee_payer=str(Keypair().pubkey()),
        payer_keypair_bytes=bytes(payer),
        recent_blockhash=str(Hash.default()),
    )


def _by_id(results: list[CheckResult]) -> dict[str, CheckResult]:
    return {r.check_id: r for r in results}


def test_conformant_facilitator_passes_the_whole_matrix() -> None:
    ctx = _context(_strict_handler)
    results = evaluate_svm_facilitator(ctx)
    assert len(results) == 7
    assert all(r.status is Status.PASS for r in results), {
        r.check_id: (r.status, r.detail) for r in results
    }


def test_thin_facilitator_passes_valid_but_fails_every_negative() -> None:
    ctx = _context(_thin_handler)
    by_id = _by_id(evaluate_svm_facilitator(ctx))
    # The valid payment is (correctly) accepted.
    assert by_id["FA-SVM-VER-001"].status is Status.PASS
    # Every structural MUST goes unenforced — the finding, made into 6 red checks.
    negatives = [f"FA-SVM-VER-00{n}" for n in range(2, 8)]
    assert all(by_id[c].status is Status.FAIL for c in negatives)
    assert "does not verify the x402 structure" in by_id["FA-SVM-VER-004"].detail


def test_absent_verify_endpoint_skips_rather_than_fails() -> None:
    ctx = _context(_absent_handler)
    results = evaluate_svm_facilitator(ctx)
    assert all(r.status is Status.SKIP for r in results)
    assert "not implemented" in results[0].detail


def test_no_context_skips_all_cases() -> None:
    results = evaluate_svm_facilitator(None)
    assert len(results) == 7
    assert all(r.status is Status.SKIP for r in results)


def test_payer_keypair_loads_from_a_solana_keygen_json_file(tmp_path: object) -> None:
    from pathlib import Path

    from solders.keypair import Keypair

    want = bytes(Keypair())
    path = Path(str(tmp_path)) / "id.json"
    path.write_text(json.dumps(list(want)), encoding="utf-8")
    assert _load_payer_keypair_bytes(str(path)) == want
