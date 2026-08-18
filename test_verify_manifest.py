"""Tests for the pre-upload manifest gate."""

import hashlib
import json
import os
import tempfile

import pytest

import verify_manifest


def _write_pair(tmp, payload=b'[{"cve":{"id":"CVE-1999-0001"}}]', sibling=True, **overrides):
    """Write a data file plus a manifest that correctly describes it."""
    data_path = os.path.join(tmp, "nvd.json")
    with open(data_path, "wb") as f:
        f.write(payload)
    if sibling:
        with open(os.path.join(tmp, "nvd.jsonl"), "wb") as f:
            f.write(payload)

    meta = {
        "bytes": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "degraded": False,
        "years_via_api": [],
    }
    meta.update(overrides)

    meta_path = os.path.join(tmp, "metadata.json")
    with open(meta_path, "w") as f:
        json.dump(meta, f)
    return data_path, meta_path


def test_verify_passes_on_a_matching_pair():
    with tempfile.TemporaryDirectory() as tmp:
        data_path, meta_path = _write_pair(tmp)
        assert verify_manifest.verify(data_path, meta_path, min_bytes=0) == []


def test_verify_flags_size_mismatch():
    with tempfile.TemporaryDirectory() as tmp:
        data_path, meta_path = _write_pair(tmp, bytes=999)
        problems = verify_manifest.verify(data_path, meta_path, min_bytes=0)

    assert any("metadata.bytes" in p for p in problems)


def test_verify_flags_hash_mismatch():
    with tempfile.TemporaryDirectory() as tmp:
        data_path, meta_path = _write_pair(tmp, sha256="0" * 64)
        problems = verify_manifest.verify(data_path, meta_path, min_bytes=0)

    assert any("metadata.sha256" in p for p in problems)


def test_verify_flags_truncated_array():
    # A half-written file: the manifest is stale, so both the shape check and
    # the size/hash checks should object.
    with tempfile.TemporaryDirectory() as tmp:
        data_path, meta_path = _write_pair(tmp, payload=b'[{"cve":{"id":"CVE-19')
        problems = verify_manifest.verify(data_path, meta_path, min_bytes=0)

    assert any("does not end with" in p for p in problems)


def test_verify_flags_degraded_run():
    with tempfile.TemporaryDirectory() as tmp:
        data_path, meta_path = _write_pair(tmp, degraded=True, years_via_api=[2023])
        problems = verify_manifest.verify(data_path, meta_path, min_bytes=0)

    assert any("degraded" in p for p in problems)


def test_verify_flags_shrink_against_published_size():
    with tempfile.TemporaryDirectory() as tmp:
        data_path, meta_path = _write_pair(tmp)
        actual = os.path.getsize(data_path)
        # Published snapshot was 10x larger: a shrink this size is never real.
        problems = verify_manifest.verify(
            data_path, meta_path, baseline_bytes=actual * 10, min_bytes=0
        )

    assert any("below the published" in p for p in problems)


def test_verify_allows_shrink_inside_the_tolerance():
    with tempfile.TemporaryDirectory() as tmp:
        data_path, meta_path = _write_pair(tmp)
        actual = os.path.getsize(data_path)
        # 1% smaller than published, inside MAX_SHRINK_RATIO.
        baseline = int(actual / (1 - 0.01))
        assert verify_manifest.verify(data_path, meta_path, baseline, min_bytes=0) == []


def test_published_bytes_returns_none_when_unreachable(monkeypatch):
    def boom(*args, **kwargs):
        raise verify_manifest.requests.RequestException("no route")

    monkeypatch.setattr(verify_manifest.requests, "get", boom)
    assert verify_manifest.published_bytes("https://example.invalid/m.json") is None


@pytest.mark.parametrize("value", [None, 0, -1, "1787783421"])
def test_published_bytes_rejects_nonsense(monkeypatch, value):
    class Resp:
        def raise_for_status(self):
            pass

        def json(self):
            return {"bytes": value}

    monkeypatch.setattr(verify_manifest.requests, "get", lambda *a, **k: Resp())
    assert verify_manifest.published_bytes("https://example.test/m.json") is None


def test_verify_enforces_the_absolute_floor_without_a_baseline():
    """The published manifest predates the `bytes` field, so the relative
    floor has nothing to compare against. Before the absolute floor existed,
    a 32-byte "dataset" with a matching manifest passed this gate."""
    with tempfile.TemporaryDirectory() as tmp:
        data_path, meta_path = _write_pair(tmp)
        problems = verify_manifest.verify(data_path, meta_path, baseline_bytes=None)

    assert any("absolute floor" in p for p in problems)


def test_verify_flags_a_jsonl_copy_that_does_not_match():
    with tempfile.TemporaryDirectory() as tmp:
        data_path, meta_path = _write_pair(tmp)
        with open(os.path.join(tmp, "nvd.jsonl"), "wb") as f:
            f.write(b"[]")
        problems = verify_manifest.verify(data_path, meta_path, min_bytes=0)

    assert any("byte-identical" in p for p in problems)


def test_verify_ignores_a_missing_jsonl_sibling():
    # main() already requires the file to exist; verify() should not blow up
    # when called directly on a lone data file.
    with tempfile.TemporaryDirectory() as tmp:
        data_path, meta_path = _write_pair(tmp, sibling=False)
        assert verify_manifest.verify(data_path, meta_path, min_bytes=0) == []
