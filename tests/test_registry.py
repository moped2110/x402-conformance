"""Internal: registry integrity across all check groups.

These guard against the kind of mistakes that silently break a shipped tool:
duplicate IDs, malformed metadata, an empty registry.
"""

from __future__ import annotations

import pytest

from x402_conformance.checks import REGISTRY, Severity, Status
from x402_conformance.checks.discovery import DI_REGISTRY
from x402_conformance.checks.facilitator import FA_REGISTRY


def _ids(reg, attr="check_id"):
    return [getattr(c, attr) for c in reg]


def _active_registry():
    pytest.importorskip("eth_account")
    from x402_conformance.checks.negative import ACTIVE_REGISTRY
    return ACTIVE_REGISTRY


def test_passive_registry_not_empty_and_has_known_checks() -> None:
    ids = set(_ids(REGISTRY))
    assert len(REGISTRY) >= 21
    for expected in ("RS-HS-001", "RS-HS-007", "RS-PR-001", "RS-PR-014"):
        assert expected in ids


def test_no_duplicate_ids_within_each_group() -> None:
    for reg in (REGISTRY, FA_REGISTRY, DI_REGISTRY, _active_registry()):
        ids = _ids(reg)
        assert len(ids) == len(set(ids)), f"duplicate ids in {ids}"


def test_no_duplicate_ids_across_all_groups() -> None:
    all_ids = _ids(REGISTRY) + _ids(FA_REGISTRY) + _ids(DI_REGISTRY) + _ids(_active_registry())
    dupes = {i for i in all_ids if all_ids.count(i) > 1}
    assert not dupes, f"check ids collide across groups: {dupes}"


def test_every_check_has_valid_metadata() -> None:
    for reg in (REGISTRY, FA_REGISTRY, DI_REGISTRY, _active_registry()):
        for c in reg:
            assert c.check_id and isinstance(c.check_id, str)
            assert c.title and isinstance(c.title, str)
            assert isinstance(c.severity, Severity)
            assert c.spec_ref and isinstance(c.spec_ref, str)
            assert callable(c.func)


def test_duplicate_registration_is_rejected() -> None:
    # the passive registry's decorator must refuse a duplicate id
    from x402_conformance.checks.base import register

    with pytest.raises(ValueError):
        @register("RS-HS-001", "dup", Severity.MAJOR, "x")
        def _dup(_s):  # pragma: no cover
            return Status.PASS, ""
