"""Evidence-bundle creation and offline integrity verification."""

from __future__ import annotations

import hashlib
import json
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from advent_prompt_pwn.core.models import RunReport
from advent_prompt_pwn.exceptions import ReportError
from advent_prompt_pwn.io import atomic_write_text, read_bounded_bytes
from advent_prompt_pwn.parsing import load_json_strict
from advent_prompt_pwn.report_io import load_report, verify_report_evidence
from advent_prompt_pwn.reporters import save_report
from advent_prompt_pwn.validation import validate_json_value

BUNDLE_VERSION = 1
MAX_BUNDLE_MANIFEST_BYTES = 1_000_000
MAX_BUNDLE_FILES = 16
MAX_BUNDLE_FILE_BYTES = 100_000_000
MAX_BUNDLE_TOTAL_BYTES = 500_000_000
DEFAULT_FORMATS = ("json", "markdown", "html", "sarif")
_FORMAT_FILENAMES = {
    "json": "report.json",
    "jsonl": "attempts.jsonl",
    "markdown": "report.md",
    "html": "report.html",
    "junit": "report.junit.xml",
    "sarif": "report.sarif",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _digest(path: Path, *, max_bytes: int | None = None) -> str:
    hasher = hashlib.sha256()
    observed = 0
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            observed += len(chunk)
            if max_bytes is not None and observed > max_bytes:
                raise ValueError(f"bundle file exceeds {max_bytes} bytes")
            hasher.update(chunk)
    return hasher.hexdigest()


@dataclass(frozen=True, slots=True)
class BundleVerification:
    """Outcome of offline bundle and report integrity checks."""

    valid: bool
    errors: tuple[str, ...]
    files_checked: int
    run_id: str | None = None


def write_evidence_bundle(
    report: RunReport,
    directory: str | Path,
    *,
    formats: tuple[str, ...] = DEFAULT_FORMATS,
    force: bool = False,
) -> Path:
    """Write reports and a checksum manifest to a dedicated directory."""

    integrity_errors = verify_report_evidence(report)
    if integrity_errors:
        raise ReportError(
            "refusing to bundle report with invalid integrity: " + "; ".join(integrity_errors)
        )
    destination = Path(directory)
    if destination.exists() and not force and any(destination.iterdir()):
        raise FileExistsError(f"refusing to overwrite non-empty bundle: {destination}")
    selected = tuple(dict.fromkeys(format_name.lower() for format_name in formats))
    if "json" not in selected:
        selected = ("json", *selected)
    unknown = sorted(set(selected) - set(_FORMAT_FILENAMES))
    if unknown:
        raise ValueError(f"unsupported bundle format(s): {', '.join(unknown)}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".appwn-bundle-", dir=destination.parent) as staging:
        staging_root = Path(staging)
        files: list[dict[str, Any]] = []
        total_bytes = 0
        for format_name in selected:
            path = save_report(
                report,
                staging_root / _FORMAT_FILENAMES[format_name],
                format_name=format_name,
            )
            size = path.stat().st_size
            if size > MAX_BUNDLE_FILE_BYTES:
                raise ValueError(f"bundle file exceeds {MAX_BUNDLE_FILE_BYTES} bytes")
            total_bytes += size
            if total_bytes > MAX_BUNDLE_TOTAL_BYTES:
                raise ValueError("bundle exceeds cumulative size limit")
            files.append(
                {
                    "path": path.name,
                    "sha256": _digest(path, max_bytes=MAX_BUNDLE_FILE_BYTES),
                    "size": size,
                }
            )
        manifest = {
            "bundle_version": BUNDLE_VERSION,
            "created_at": _now(),
            "run_id": report.run_id,
            "engagement_id": report.engagement_id,
            "target_name": report.target_name,
            "corpus_sha256": report.corpus_sha256,
            "files": files,
        }
        manifest_path = staging_root / "bundle-manifest.json"
        atomic_write_text(manifest_path, json.dumps(manifest, indent=2, sort_keys=True))
        total_bytes += manifest_path.stat().st_size
        if total_bytes > MAX_BUNDLE_TOTAL_BYTES:
            raise ValueError("bundle exceeds cumulative size limit")

        allowed_members = {*_FORMAT_FILENAMES.values(), "bundle-manifest.json"}
        if destination.exists():
            unexpected = next(
                (
                    member
                    for member in destination.iterdir()
                    if member.name not in allowed_members or not member.is_file()
                ),
                None,
            )
            if unexpected is not None:
                raise FileExistsError(
                    "refusing to replace bundle containing unexpected member: "
                    f"{unexpected.name}"
                )
        destination.mkdir(parents=True, exist_ok=True)
        if force:
            for filename in allowed_members:
                stale = destination / filename
                if stale.exists():
                    stale.unlink()
        for staged in staging_root.iterdir():
            staged.replace(destination / staged.name)
    return destination


def verify_evidence_bundle(directory: str | Path) -> BundleVerification:
    """Verify manifest checksums and per-attempt evidence hashes."""

    root = Path(directory).resolve()
    manifest_path = root / "bundle-manifest.json"
    try:
        manifest_bytes = read_bounded_bytes(
            manifest_path,
            MAX_BUNDLE_MANIFEST_BYTES,
            label="bundle manifest",
        )
        raw: Any = load_json_strict(manifest_bytes.decode("utf-8"))
        validate_json_value(
            raw,
            label="bundle manifest",
            max_nodes=10_000,
            max_collection_items=MAX_BUNDLE_FILES,
        )
    except (
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
        ValueError,
    ) as exc:
        return BundleVerification(False, (f"could not read bundle manifest: {exc}",), 0)
    if not isinstance(raw, dict) or raw.get("bundle_version") != BUNDLE_VERSION:
        return BundleVerification(False, ("unsupported or invalid bundle manifest",), 0)
    entries = raw.get("files")
    if not isinstance(entries, list) or not entries:
        return BundleVerification(False, ("bundle file list is invalid",), 0)
    if len(entries) > MAX_BUNDLE_FILES:
        return BundleVerification(False, ("bundle contains too many file entries",), 0)
    errors: list[str] = []
    checked = 0
    total_bytes = 0
    seen_paths: set[str] = set()
    allowed_paths = set(_FORMAT_FILENAMES.values())
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
            errors.append("invalid bundle file entry")
            continue
        entry_path = entry["path"]
        if entry_path in seen_paths:
            errors.append(f"duplicate bundle path: {entry_path}")
            continue
        seen_paths.add(entry_path)
        if entry_path not in allowed_paths:
            errors.append(f"unexpected bundle path: {entry_path}")
            continue
        expected_size = entry.get("size")
        expected_digest = entry.get("sha256")
        if (
            isinstance(expected_size, bool)
            or not isinstance(expected_size, int)
            or expected_size < 0
            or expected_size > MAX_BUNDLE_FILE_BYTES
        ):
            errors.append(f"invalid size for {entry_path}")
            continue
        if (
            not isinstance(expected_digest, str)
            or len(expected_digest) != 64
            or any(character not in "0123456789abcdef" for character in expected_digest)
        ):
            errors.append(f"invalid checksum for {entry_path}")
            continue
        candidate = (root / entry_path).resolve()
        if not candidate.is_relative_to(root) or candidate.parent != root:
            errors.append(f"unsafe bundle path: {entry_path}")
            continue
        try:
            observed_size = candidate.stat().st_size
            if observed_size > MAX_BUNDLE_FILE_BYTES:
                errors.append(f"bundle file exceeds size limit: {entry_path}")
                continue
            total_bytes += observed_size
            if total_bytes > MAX_BUNDLE_TOTAL_BYTES:
                errors.append("bundle exceeds cumulative size limit")
                break
            observed_digest = _digest(candidate, max_bytes=MAX_BUNDLE_FILE_BYTES)
        except (OSError, ValueError) as exc:
            errors.append(f"could not read {entry_path}: {exc}")
            continue
        checked += 1
        if observed_size != expected_size:
            errors.append(f"size mismatch for {entry_path}")
        if observed_digest != expected_digest:
            errors.append(f"checksum mismatch for {entry_path}")
    if "report.json" not in seen_paths:
        errors.append("bundle manifest is missing report.json")
    try:
        actual_members: set[str] = set()
        for index, item in enumerate(root.iterdir(), start=1):
            if index > MAX_BUNDLE_FILES + 1:
                errors.append("bundle contains too many directory members")
                break
            actual_members.add(item.name)
    except OSError as exc:
        errors.append(f"could not enumerate bundle: {exc}")
        actual_members = set()
    expected_members = {*seen_paths, "bundle-manifest.json"}
    for unexpected in sorted(actual_members - expected_members):
        errors.append(f"unlisted bundle member: {unexpected}")
    report_path = root / "report.json"
    run_id: str | None = None
    if report_path.exists():
        try:
            report = load_report(report_path)
            run_id = report.run_id
            errors.extend(verify_report_evidence(report))
            if raw.get("run_id") != report.run_id:
                errors.append("bundle run id does not match report")
            if raw.get("engagement_id") != report.engagement_id:
                errors.append("bundle engagement id does not match report")
            if raw.get("target_name") != report.target_name:
                errors.append("bundle target name does not match report")
            if raw.get("corpus_sha256") != report.corpus_sha256:
                errors.append("bundle corpus digest does not match report")
        except ReportError as exc:
            errors.append(str(exc))
    else:
        errors.append("bundle is missing report.json")
    return BundleVerification(not errors, tuple(errors), checked, run_id)
