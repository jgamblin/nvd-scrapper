"""Smoke test for the streaming writer in nvd.py.

This test exercises the JSON-array streaming logic without hitting the
real NVD API. It feeds a fake page iterator into `write_stream()` and
asserts the output is valid JSON containing every item.
"""

import json
import os
import tempfile
from unittest.mock import Mock

import nvd
import pytest
import requests


def test_write_stream_produces_valid_json_array():
    fake_pages = [
        [{"cve": {"id": "CVE-2025-0001"}}, {"cve": {"id": "CVE-2025-0002"}}],
        [{"cve": {"id": "CVE-2025-0003"}}],
        [],  # Empty final page (mimics exhausted pagination)
    ]

    with tempfile.TemporaryDirectory() as tmp:
        out_path = os.path.join(tmp, "nvd.json")
        count = nvd.write_stream(iter(fake_pages), out_path)

        assert count == 3

        with open(out_path) as f:
            data = json.load(f)

        assert isinstance(data, list)
        assert len(data) == 3
        assert data[0]["cve"]["id"] == "CVE-2025-0001"
        assert data[2]["cve"]["id"] == "CVE-2025-0003"


def test_write_stream_handles_empty_input():
    with tempfile.TemporaryDirectory() as tmp:
        out_path = os.path.join(tmp, "nvd.json")
        count = nvd.write_stream(iter([]), out_path)

        assert count == 0

        with open(out_path) as f:
            data = json.load(f)

        assert data == []


class DummyResponse:
    def __init__(self, status_code: int, payload: dict, headers=None):
        self.status_code = status_code
        self._payload = payload
        self.headers = headers or {}

    def raise_for_status(self):
        if self.status_code >= 400:
            err = requests.HTTPError(f"HTTP {self.status_code}")
            err.response = self
            raise err

    def json(self):
        return self._payload


def test_iter_pages_retries_then_succeeds(monkeypatch):
    session = Mock()
    session.get = Mock(
        side_effect=[
            DummyResponse(429, {"message": "rate limited"}, headers={"Retry-After": "1"}),
            DummyResponse(200, {"vulnerabilities": [{"cve": {"id": "CVE-2025-0001"}}]}),
        ]
    )

    sleeps = []
    monkeypatch.setattr(nvd.time, "sleep", lambda s: sleeps.append(s))

    pages = list(nvd.iter_pages(session, {}, total=1))

    assert len(pages) == 1
    assert pages[0][0]["cve"]["id"] == "CVE-2025-0001"
    assert sleeps == [1.0]


def test_iter_pages_raises_when_retries_exhausted(monkeypatch):
    session = Mock()
    session.get = Mock(side_effect=[DummyResponse(500, {"message": "boom"})] * 3)

    monkeypatch.setattr(nvd, "MAX_RETRIES_PER_PAGE", 3)
    monkeypatch.setattr(nvd.time, "sleep", lambda _: None)

    with pytest.raises(RuntimeError, match="Failed to fetch page"):
        list(nvd.iter_pages(session, {}, total=1))
