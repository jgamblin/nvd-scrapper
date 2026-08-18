"""Pre-upload gate: prove metadata.json describes the nvd.json we just built.

Runs in CI between the scrape and the R2 upload. Exits non-zero if the
manifest and the data file disagree, if the run was degraded, or if the file
is materially smaller than the snapshot already on the mirror.

Two size floors apply. The relative one (against the published snapshot) is
the useful check, but it is only available once a manifest carrying `bytes`
has actually been published -- which is not true of the first run after this
gate ships. So an absolute floor backs it up and always applies. The fixed
100 MB floor this replaces was about 5% of the real file size and never fired
on any regression that reached consumers.
"""

import hashlib
import json
import os
import sys

import requests

BASELINE_METADATA_URL = os.environ.get(
    "BASELINE_METADATA_URL", "https://nvd.handsonhacking.org/metadata.json"
)
# Refuse to publish a file more than this fraction smaller than the published
# one. Per-year and total non-regression already run inside nvd.py; this is a
# blunt backstop against a truncated or half-written file.
MAX_SHRINK_RATIO = 0.02
# Backstop for when the published manifest predates the `bytes` field, or the
# mirror is unreachable. The corpus only grows and the object has been over
# 1.7 GB since well before this was written, so 1 GB is a floor no healthy run
# can trip. Overridable so a restricted-range build can still be checked.
ABSOLUTE_MIN_BYTES = int(os.environ.get("MIN_DATA_BYTES", 1_000_000_000))
REQUIRED_OUTPUTS = ("nvd.json", "nvd.jsonl", "metadata.json")


def sha256_file(path: str, chunk_size: int = 8 * 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def published_bytes(url: str = BASELINE_METADATA_URL) -> int | None:
    """Byte size of the snapshot currently on the mirror, or None.

    Best-effort: nvd.py already refuses to publish without a baseline, so an
    unreachable mirror here falls back to ABSOLUTE_MIN_BYTES rather than
    blocking a run twice for the same reason. The same fallback covers a
    published manifest that predates the `bytes` field.
    """
    if not url:
        return None
    try:
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
        value = resp.json().get("bytes")
    except (requests.RequestException, ValueError, AttributeError) as exc:
        print(f"warning: published metadata unavailable ({exc})", file=sys.stderr)
        return None
    return value if isinstance(value, int) and value > 0 else None


def check_json_array_shape(path: str) -> list[str]:
    """Cheap structural check that the file is a complete JSON array."""
    size = os.path.getsize(path)
    if size < 2:
        return [f"{path} is too small to be a JSON array ({size} bytes)"]
    with open(path, "rb") as f:
        first = f.read(1)
        f.seek(-1, os.SEEK_END)
        last = f.read(1)
    problems = []
    if first != b"[":
        problems.append(f"{path} does not start with '['")
    if last != b"]":
        problems.append(f"{path} does not end with ']' (truncated write?)")
    return problems


def verify(
    data_path: str = "nvd.json",
    metadata_path: str = "metadata.json",
    baseline_bytes: int | None = None,
    min_bytes: int | None = None,
) -> list[str]:
    """Return a list of problems (empty list == safe to upload)."""
    if min_bytes is None:
        min_bytes = ABSOLUTE_MIN_BYTES
    with open(metadata_path) as f:
        meta = json.load(f)
    if not isinstance(meta, dict):
        return [f"{metadata_path} is not a JSON object"]

    problems = check_json_array_shape(data_path)

    actual_bytes = os.path.getsize(data_path)
    if meta.get("bytes") != actual_bytes:
        problems.append(
            f"metadata.bytes {meta.get('bytes')} != {data_path} {actual_bytes}"
        )

    actual_sha = sha256_file(data_path)
    if meta.get("sha256") != actual_sha:
        problems.append(
            f"metadata.sha256 {meta.get('sha256')} != {data_path} {actual_sha}"
        )

    # Belt and braces: the API fallback is disabled for full-corpus runs, so a
    # degraded run should be impossible here rather than merely flagged.
    if meta.get("degraded"):
        problems.append(
            f"run is degraded (years_via_api={meta.get('years_via_api')})"
        )

    # nvd.jsonl is a byte-identical copy, so a size mismatch means the copy or
    # the write behind it went wrong. Cheap enough to always check.
    sibling = os.path.join(os.path.dirname(data_path), "nvd.jsonl")
    if os.path.exists(sibling):
        sibling_bytes = os.path.getsize(sibling)
        if sibling_bytes != actual_bytes:
            problems.append(
                f"{sibling} is {sibling_bytes} bytes but {data_path} is "
                f"{actual_bytes}; they are meant to be byte-identical"
            )

    if actual_bytes < min_bytes:
        problems.append(
            f"{data_path} is {actual_bytes} bytes, below the absolute floor "
            f"{min_bytes}"
        )

    if baseline_bytes:
        floor = int(baseline_bytes * (1 - MAX_SHRINK_RATIO))
        if actual_bytes < floor:
            problems.append(
                f"{data_path} is {actual_bytes} bytes, more than "
                f"{MAX_SHRINK_RATIO:.0%} below the published {baseline_bytes}"
            )

    return problems


def main() -> int:
    missing = [p for p in REQUIRED_OUTPUTS if not os.path.exists(p)]
    if missing:
        print(f"missing required output(s): {', '.join(missing)}", file=sys.stderr)
        return 1

    problems = verify(baseline_bytes=published_bytes())
    for problem in problems:
        print(f"verify failed: {problem}", file=sys.stderr)
    if problems:
        return 1

    print(
        f"verify OK: manifest matches nvd.json "
        f"({os.path.getsize('nvd.json')} bytes)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
