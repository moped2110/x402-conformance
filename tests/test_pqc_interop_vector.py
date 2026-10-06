"""The shared receipt-v2 vector that psv verifies too.

The PQC checks re-implement psv's receipt-v2 canonicalization instead of importing psv,
so nothing would notice if the two drifted. Both repositories carry a byte-identical
copy of ``receipt-v2-interop.json`` (here ``tests/fixtures/pqc/``, in psv
``tests/pqc/vectors/``) and verify it with their own code: a change to either
canonicalization breaks the recorded hash in that repository.
"""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

pytest.importorskip("cryptography.hazmat.primitives.asymmetric.mldsa")

from x402_conformance.checks.pqc import _canonical, _verify  # noqa: E402
from x402_conformance.probe import ProbeSession  # noqa: E402

_VECTOR = Path(__file__).parent / "fixtures" / "pqc" / "receipt-v2-interop.json"
# Pins the copy itself: the psv copy is pinned to the same digest.
_VECTOR_FILE_SHA256 = "c5128fea711a2a483333221e82b700650d1e9cadd9c350bf9ce430561c8ceca7"


def _load() -> dict[str, object]:
    """Read the vector and fail loudly if this copy was edited on its own."""
    raw = _VECTOR.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == _VECTOR_FILE_SHA256, (
        "receipt-v2-interop.json changed; update the psv copy in the same change"
    )
    vector = json.loads(raw)
    assert isinstance(vector, dict)
    return vector


def _session(vector: dict[str, object]) -> ProbeSession:
    """Advertise the vector's receipt and keys the way a 402 `extensions.pqc` would."""
    raw = {"extensions": {"pqc": {"receipt": vector["receipt"], "keys": vector["keys"]}}}
    return cast(ProbeSession, SimpleNamespace(first=SimpleNamespace(raw=raw)))


def test_canonical_bytes_match_the_shared_digest() -> None:
    """The checks' canonical bytes hash to the digest psv also asserts."""
    vector = _load()
    receipt = vector["receipt"]
    assert isinstance(receipt, dict)
    assert hashlib.sha256(_canonical(receipt)).hexdigest() == vector["canonical_sha256"]


def test_shared_vector_verifies() -> None:
    """Both signatures in the shared vector verify with the checks' own verifier."""
    vector = _load()
    assert _verify(_session(vector)) == (True, True)


def test_shared_vector_rejects_a_changed_business_field() -> None:
    """Changing a covered non-ASCII field invalidates both signatures."""
    vector = _load()
    receipt = copy.deepcopy(vector["receipt"])
    assert isinstance(receipt, dict)
    receipt["memo"] = "Cafe"
    assert _verify(_session(vector), receipt) == (False, False)
