"""The shared receipt-v2 vector that psv verifies too.

The PQC checks re-implement psv's receipt-v2 canonicalization instead of importing psv,
so nothing would notice if the two drifted. Both repositories carry a byte-identical
copy of ``receipt-v2-interop.json`` (here ``tests/fixtures/pqc/``, in psv
``tests/pqc/vectors/``) and verify it with their own code: a change to either
canonicalization breaks the recorded hash in that repository. Its ``rejected`` texts
must be refused by both with the same error, so the two also agree on what is *not* a
valid receipt.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import httpx
import pytest

pytest.importorskip("cryptography.hazmat.primitives.asymmetric.mldsa")

from x402_conformance.checks.base import Status  # noqa: E402
from x402_conformance.checks.pqc import _canonical, _verify, pqc_002  # noqa: E402
from x402_conformance.probe import PAYMENT_REQUIRED_HEADER, ProbeSession, build_probe  # noqa: E402

_VECTOR = Path(__file__).parent / "fixtures" / "pqc" / "receipt-v2-interop.json"
# Pins the copy itself: the psv copy is pinned to the same digest.
_VECTOR_FILE_SHA256 = "b8d8621efc7c0469b546853a6d150cc81a46e9dda9d7b77817990d9e27021e8a"


def _load() -> dict[str, object]:
    """Read the vector and fail loudly if this copy was edited on its own."""
    raw = _VECTOR.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == _VECTOR_FILE_SHA256, (
        "receipt-v2-interop.json changed; update the psv copy in the same change"
    )
    vector = json.loads(raw)
    assert isinstance(vector, dict)
    return vector


def _rejected_cases() -> list[dict[str, str]]:
    """The shared texts both implementations must refuse, read at collection time."""
    rejected = json.loads(_VECTOR.read_bytes())["rejected"]
    assert isinstance(rejected, list) and rejected
    return rejected


def _session_from_text(receipt_json: str, keys: object, *, extra: str = "") -> ProbeSession:
    """Serve ``receipt_json`` verbatim inside a 402 challenge and probe it.

    The receipt text is spliced into the challenge unparsed, so floats, ``NaN`` and
    repeated member names reach the probe exactly as a server would send them.
    """
    challenge = (
        '{"x402Version":2'
        + extra
        + ',"extensions":{"pqc":{"receipt":'
        + receipt_json
        + ',"keys":'
        + json.dumps(keys)
        + "}}}"
    )
    header = base64.b64encode(challenge.encode("utf-8")).decode("ascii")
    probe = build_probe(httpx.Response(402, headers={PAYMENT_REQUIRED_HEADER: header}))
    return cast(ProbeSession, SimpleNamespace(first=probe))


def _session(vector: dict[str, object]) -> ProbeSession:
    """Advertise the vector's receipt and keys the way a 402 `extensions.pqc` would."""
    receipt_json = json.dumps(vector["receipt"], ensure_ascii=False)
    return _session_from_text(receipt_json, vector["keys"])


def test_canonical_bytes_match_the_shared_digest() -> None:
    """The checks' canonical bytes hash to the digest psv also asserts."""
    vector = _load()
    receipt = vector["receipt"]
    assert isinstance(receipt, dict)
    assert hashlib.sha256(_canonical(receipt)).hexdigest() == vector["canonical_sha256"]


def test_shared_vector_verifies() -> None:
    """Both signatures in the shared vector verify with the checks' own verifier."""
    vector = _load()
    session = _session(vector)
    assert _verify(session) == (True, True)
    assert pqc_002(session)[0] is Status.PASS


def test_shared_vector_rejects_a_changed_business_field() -> None:
    """Changing a covered non-ASCII field invalidates both signatures."""
    vector = _load()
    receipt = copy.deepcopy(vector["receipt"])
    assert isinstance(receipt, dict)
    receipt["memo"] = "Cafe"
    assert _verify(_session(vector), receipt) == (False, False)


@pytest.mark.parametrize("case", _rejected_cases(), ids=lambda case: case["name"])
def test_shared_rejections_fail_with_the_shared_error(case: dict[str, str]) -> None:
    """Floats, NaN, repeated and non-ASCII member names fail with psv's exact error."""
    vector = _load()
    session = _session_from_text(case["receipt_json"], vector["keys"])
    assert pqc_002(session) == (Status.FAIL, case["error"])
    with pytest.raises(ValueError) as excinfo:
        _verify(session)
    assert str(excinfo.value) == case["error"]


def test_a_repeated_member_outside_the_receipt_is_not_a_receipt_finding() -> None:
    """Only the receipt subtree is held to psv's duplicate rule.

    A repeated key elsewhere in the challenge is reported by the JSON-hygiene checks;
    it must not make an otherwise valid receipt fail the PQC profile.
    """
    vector = _load()
    receipt_json = json.dumps(vector["receipt"], ensure_ascii=False)
    session = _session_from_text(receipt_json, vector["keys"], extra=',"resource":1,"resource":2')
    assert session.first.duplicate_json_keys == ("resource",)
    assert pqc_002(session)[0] is Status.PASS
    assert _verify(session) == (True, True)


@pytest.mark.parametrize(
    ("value", "error"),
    [
        (1.5, "receipt numbers must be integers; decimal amounts use strings"),
        (float("nan"), "receipt numbers must be integers; decimal amounts use strings"),
        (b"bytes", "receipt contains a non-JSON value"),
        ({1: "x"}, "receipt object keys must be ASCII strings"),
    ],
)
def test_canonical_refuses_values_psv_refuses(value: object, error: str) -> None:
    """Values built in Python (as PQC-006 does) meet the same profile as parsed ones."""
    receipt = copy.deepcopy(_load()["receipt"])
    assert isinstance(receipt, dict)
    receipt["extra"] = value
    with pytest.raises(ValueError, match=error.replace("(", r"\(")):
        _canonical(receipt)
