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


def test_shared_duplicate_guard_rejects_duplicates_for_every_registry() -> None:
    from x402_conformance.checks.base import append_unique_check

    for registry in (REGISTRY, FA_REGISTRY, DI_REGISTRY, _active_registry()):
        isolated = [registry[0]]
        with pytest.raises(ValueError, match="duplicate check id"):
            append_unique_check(isolated, registry[0], registry[0].check_id)


# --- Catalog ↔ code drift guard -------------------------------------------
#
# The catalog (docs/conformance-catalog.md) advertises an "Implemented & tested
# (N checks)" set. It is hand-maintained and easy to drift from the actual code
# — especially for checks that aren't in a decorator registry (RS-PAY, FA-SET).
# These tests pin the two together.

import re  # noqa: E402
from pathlib import Path  # noqa: E402

import httpx  # noqa: E402

_CATALOG = Path(__file__).resolve().parents[1] / "docs" / "conformance-catalog.md"
_README = Path(__file__).resolve().parents[1] / "README.md"
_SUPPORT_MATRIX = Path(__file__).resolve().parents[1] / "docs" / "support-matrix.md"
_UPSTREAM_PIN = Path(__file__).resolve().parents[1] / ".github" / "upstream-reviewed-commit"


def _all_implemented_ids() -> set[str]:
    """Every check ID the tool can actually emit, across all groups.

    Includes the registry-less groups (RS-PAY/RS-SEC settlement, FA-SET) by
    invoking their evaluators with an empty context, which yields SKIP results
    carrying the IDs.
    """
    from x402_conformance.checks.facilitator import FacilitatorContext, evaluate_settle
    from x402_conformance.checks.payment import evaluate_payment
    from x402_conformance.checks.timing import evaluate_timing

    ids: set[str] = set()
    for reg in (REGISTRY, FA_REGISTRY, DI_REGISTRY, _active_registry()):
        ids |= {c.check_id for c in reg}
    ids |= {r.check_id for r in evaluate_payment(None)}
    ids |= {r.check_id for r in evaluate_timing(None)}
    with httpx.Client() as client:
        ctx = FacilitatorContext(
            base_url="", client=client, requirements=None, signer=None, allow_settle=False
        )
        ids |= {r.check_id for r in evaluate_settle(ctx)}
    return ids


def test_every_implemented_check_is_in_the_catalog() -> None:
    catalog = _CATALOG.read_text(encoding="utf-8")
    missing = sorted(i for i in _all_implemented_ids() if i not in catalog)
    assert not missing, f"implemented checks missing from the catalog: {missing}"


def test_catalog_implemented_count_matches_code() -> None:
    catalog = _CATALOG.read_text(encoding="utf-8")
    m = re.search(r"Implemented & tested \((\d+) checks\)", catalog)
    assert m, "catalog is missing its 'Implemented & tested (N checks)' marker"
    stated = int(m.group(1))
    actual = len(_all_implemented_ids())
    assert stated == actual, (
        f"catalog says {stated} implemented checks, code emits {actual} — update "
        "the catalog's implementation-status section"
    )


def _catalog_rows() -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    for line in _CATALOG.read_text(encoding="utf-8").splitlines():
        if not re.match(r"^\| (?:(?:RS|FA)-[A-Z]+-[0-9]{3}|DI-[0-9]{3}) \|", line):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        assert len(cells) == 6, f"catalog row has no explicit status column: {line}"
        rows.append((cells[0], cells[-1]))
    return rows


def test_catalog_ids_are_unique_and_every_row_has_explicit_status() -> None:
    rows = _catalog_rows()
    ids = [check_id for check_id, _ in rows]
    assert len(ids) == len(set(ids)), f"duplicate catalog IDs: {ids}"
    assert all(status in {"implemented", "planned"} for _, status in rows)
    assert {cid for cid, status in rows if status == "planned"} == {
        "RS-NEG-010",
        "FA-VER-001",
        "FA-VER-005",
    }


def test_every_implemented_id_has_exactly_one_implemented_catalog_row() -> None:
    rows = _catalog_rows()
    implemented = _all_implemented_ids()
    assert {check_id for check_id, status in rows if status == "implemented"} == implemented
    for check_id in implemented:
        assert rows.count((check_id, "implemented")) == 1, check_id


def test_readme_check_count_matches_code() -> None:
    # The README headline "N checks across the groups above" is a sales figure a
    # reader trusts. Pin it to the code so it can never quietly go stale again.
    readme = _README.read_text(encoding="utf-8")
    m = re.search(r"(\d+) checks across the groups above", readme)
    assert m, "README is missing its 'N checks across the groups above' marker"
    stated = int(m.group(1))
    actual = len(_all_implemented_ids())
    assert stated == actual, (
        f"README says {stated} checks, code emits {actual} — update the README headline"
    )


def test_support_matrix_and_upstream_drift_pin_match() -> None:
    matrix = _SUPPORT_MATRIX.read_text(encoding="utf-8")
    reviewed = _UPSTREAM_PIN.read_text(encoding="utf-8").strip()
    assert re.fullmatch(r"[0-9a-f]{7}", reviewed)
    assert f"main@{reviewed}" in matrix
    for status in ("supported", "passive-only", "planned", "out of scope"):
        assert status in matrix
