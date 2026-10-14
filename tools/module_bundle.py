#!/usr/bin/env python3
"""Offline source-kit bundle builder/verifier. Not an APK loader or native-code installer."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import sys
import tempfile
import zipfile

BUNDLE_ID = "org.wininstaller.compatlab"
VERSION = "0.3.0"
FORMAT = 1
LIMIT = 8 * 1024 * 1024
MEMBERS = {
    "include/winclab/file_api.h": "winclab-file",
    "src/file_api.cpp": "winclab-file",
    "include/winclab/registry_api.h": "winclab-registry",
    "src/registry_api.cpp": "winclab-registry",
}
ROOT = Path(__file__).resolve().parents[1]


class BundleError(ValueError):
    pass


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def normalize_name(name: str) -> str:
    if not isinstance(name, str) or "\\" in name or "\x00" in name or name.startswith("/"):
        raise BundleError("unsafe archive name")
    path = PurePosixPath(name)
    if str(path) != name or any(x in (".", "..", "") for x in name.split("/")):
        raise BundleError("unsafe archive path")
    return name


def _zipadd(zf: zipfile.ZipFile, name: str, contents: bytes) -> None:
    info = zipfile.ZipInfo(name, date_time=(2020, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = (stat.S_IFREG | 0o644) << 16
    zf.writestr(info, contents)


def build(output: Path, source_root: Path = ROOT) -> str:
    files = {}
    payload = {}
    for name, module in sorted(MEMBERS.items()):
        data = (source_root / name).read_bytes()
        if not data or len(data) > LIMIT:
            raise BundleError("invalid source file size")
        payload[name] = data
        files[name] = {"sha256": sha256(data), "size": len(data), "module": module}
    manifest = {
        "schema": FORMAT,
        "package_id": BUNDLE_ID,
        "version": VERSION,
        "kind": "source-kit",
        "host_api": 1,
        "modules": sorted(set(MEMBERS.values())),
        "files": files,
        "activation": "not-supported-without-private-host-integration",
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        _zipadd(zf, "manifest.json", (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode())
        for name, data in sorted(payload.items()):
            _zipadd(zf, name, data)
    verify(output)
    return sha256(output.read_bytes())


def verify(archive: Path, expected_sha: str | None = None) -> tuple[dict, dict[str, bytes]]:
    if not archive.is_file() or archive.stat().st_size > LIMIT:
        raise BundleError("archive missing or exceeds limit")
    if expected_sha is not None:
        if len(expected_sha) != 64 or any(c not in "0123456789abcdefABCDEF" for c in expected_sha):
            raise BundleError("invalid trusted SHA-256")
        if sha256(archive.read_bytes()) != expected_sha.lower():
            raise BundleError("bundle digest differs from trusted digest")
    with zipfile.ZipFile(archive, "r") as zf:
        entries = zf.infolist()
        if len(entries) != len(MEMBERS) + 1:
            raise BundleError("unexpected number of bundle entries")
        names = [normalize_name(e.filename) for e in entries]
        if len(names) != len(set(names)) or set(names) != set(MEMBERS) | {"manifest.json"}:
            raise BundleError("unexpected or duplicate files in bundle")
        for item in entries:
            mode = item.external_attr >> 16
            if item.is_dir() or (mode and not stat.S_ISREG(mode)) or item.file_size > LIMIT:
                raise BundleError("archive contains unsafe member")
        if sum(e.file_size for e in entries) > LIMIT:
            raise BundleError("uncompressed content exceeds limit")
        content = {name: zf.read(name) for name in names}
    try:
        manifest = json.loads(content.pop("manifest.json").decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise BundleError("invalid manifest JSON") from exc
    if not isinstance(manifest, dict) or manifest.get("schema") != FORMAT or manifest.get("package_id") != BUNDLE_ID:
        raise BundleError("unknown bundle schema or identity")
    if (manifest.get("version") != VERSION or manifest.get("kind") != "source-kit"
            or manifest.get("host_api") != 1 or manifest.get("activation") != "not-supported-without-private-host-integration"
            or manifest.get("modules") != sorted(set(MEMBERS.values()))):
        raise BundleError("unsupported bundle metadata")
    records = manifest.get("files")
    if not isinstance(records, dict) or set(records) != set(MEMBERS):
        raise BundleError("invalid manifest file table")
    for name, data in content.items():
        if records[name] != {"sha256": sha256(data), "size": len(data), "module": MEMBERS[name]}:
            raise BundleError("file digest, length or module differs from manifest")
    return manifest, content


def stage(archive: Path, destination: Path, trusted_sha: str, contract_file: Path) -> Path:
    manifest, content = verify(archive, trusted_sha)
    contract = json.loads(contract_file.read_text(encoding="utf-8"))
    if (contract.get("consumer") != "wininstaller" or contract.get("host_api") != 1
            or contract.get("allow_source_kits") is not True
            or not set(manifest["modules"]).issubset(set(contract.get("allowed_modules", [])))):
        raise BundleError("host does not authorize this source kit")
    destination = destination.resolve()
    destination.mkdir(parents=True, exist_ok=True)
    target = destination / (BUNDLE_ID + "-" + VERSION)
    if target.exists() or target.is_symlink():
        raise BundleError("target already exists; never overwrite installed files")
    tmp = Path(tempfile.mkdtemp(prefix=".winclab-stage-", dir=destination))
    try:
        for name, data in content.items():
            file = tmp / name
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_bytes(data)
        (tmp / "manifest.json").write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        os.replace(tmp, target)
    finally:
        if tmp.exists():
            shutil.rmtree(tmp)
    return target


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build, verify or stage an OFFLINE source-kit bundle (no APK modification).")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("build")
    p.add_argument("--out", type=Path, default=Path("dist/WinInstaller-CompatLab-0.3.0.wicmod"))
    p = sub.add_parser("verify")
    p.add_argument("bundle", type=Path)
    p.add_argument("--expected-sha256")
    p = sub.add_parser("stage")
    p.add_argument("bundle", type=Path)
    p.add_argument("--trust-sha256", required=True)
    p.add_argument("--host-contract", type=Path, required=True)
    p.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "build":
            digest = build(args.out)
            print(f"BUILT {args.out} SHA256={digest}")
        elif args.command == "verify":
            manifest, _ = verify(args.bundle, args.expected_sha256)
            print(json.dumps({"verified": True, "package_id": manifest["package_id"], "version": manifest["version"], "kind": manifest["kind"]}))
        else:
            path = stage(args.bundle, args.destination, args.trust_sha256, args.host_contract)
            print(f"STAGED {path} (NOT LOADED OR ACTIVATED)")
    except (BundleError, OSError, ValueError, zipfile.BadZipFile, KeyError) as e:
        print(f"BUNDLE_REJECTED: {type(e).__name__}: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
