#!/usr/bin/env python3
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import tomllib

NOTICE_FILE_LIMIT = 2 * 1024 * 1024


def license_files(package):
    root = Path(package["manifest_path"]).parent.resolve()
    candidates = set()
    for pattern in ("LICENSE*", "LICENCE*", "COPYING*", "NOTICE*", "license*", "licence*"):
        candidates.update(path for path in root.glob(pattern) if path.is_file())
    for directory in ("LICENSES", "licenses"):
        candidates.update(path for path in (root / directory).glob("*") if path.is_file())
    declared = package.get("license_file")
    if declared:
        path = (root / declared).resolve()
        if path.is_relative_to(root) and path.is_file():
            candidates.add(path)
    if not candidates and str(package.get("source", "")).startswith(
        "git+https://github.com/OpenCloudGaming/opennow"
    ):
        for parent in list(root.parents)[:4]:
            candidate = parent / "LICENSE"
            if candidate.is_file():
                candidates.add(candidate)
                break
    return sorted(candidates)


def indexed_files(root, entry, expected_status="upstream-at-published-commit"):
    if entry.get("status") != expected_status:
        raise ValueError("Supplemental notice lacks published-source provenance")
    files = []
    for record in entry["files"]:
        relative = Path(record["path"])
        path = (root / relative).resolve()
        if relative.is_absolute() or ".." in relative.parts or not path.is_relative_to(root.resolve()):
            raise ValueError("Supplemental notice escapes its directory")
        if path.stat().st_size > NOTICE_FILE_LIMIT:
            raise ValueError("Supplemental notice exceeds the bound")
        if hashlib.sha256(path.read_bytes()).hexdigest() != record["sha256"]:
            raise ValueError("Supplemental notice hash mismatch")
        files.append(path)
    if not files:
        raise ValueError("Supplemental notice has no files")
    return files


def append_files(output, files):
    seen = set()
    for path in files:
        if path.stat().st_size > NOTICE_FILE_LIMIT:
            raise ValueError(f"License file exceeds the bound: {path.name}")
        data = path.read_bytes()
        digest = hashlib.sha256(data).digest()
        if digest not in seen:
            output.extend([f"--- {path.name} ---", data.decode("utf-8"), ""])
            seen.add(digest)


def generate(metadata, supplement_root, lock_packages, toolchain, toolchain_commit):
    index = json.loads((supplement_root / "index.json").read_text(encoding="utf-8"))
    if index.get("schema") != 1:
        raise ValueError("Unsupported supplemental notice index")
    workspace = set(metadata["workspace_members"])
    graph = {node["id"]: node["dependencies"] for node in metadata["resolve"]["nodes"]}
    reachable = set()
    pending = list(workspace)
    while pending:
        identity = pending.pop()
        if identity not in reachable:
            reachable.add(identity)
            pending.extend(graph[identity])
    packages = sorted(
        (package for package in metadata["packages"]
         if package["id"] in reachable and package["id"] not in workspace),
        key=lambda package: (package["name"], package["version"]),
    )
    output = ["Third-party dependency notices", "==============================", ""]
    missing = []
    for package in packages:
        files = license_files(package)
        key = f'{package["name"]}@{package["version"]}'
        if not files and key in index["packages"]:
            entry = index["packages"][key]
            locked = next((item for item in lock_packages
                           if item["name"] == package["name"]
                           and item["version"] == package["version"]
                           and item.get("source") == package.get("source")), None)
            if not locked or not locked.get("checksum") or locked["checksum"] != entry.get("cargo_lock_checksum"):
                raise ValueError(f"Supplemental notice lock checksum mismatch: {key}")
            if entry.get("license") != package.get("license"):
                raise ValueError(f"Supplemental declared license mismatch: {key}")
            try:
                files = indexed_files(supplement_root, entry)
            except ValueError as error:
                missing.append(f"{key}: {error}")
                continue
        if not files:
            missing.append(f'{package["name"]} {package["version"]}')
            continue
        output.extend([
            f'{package["name"]} {package["version"]}',
            f'Declared license: {package.get("license") or "see license text"}',
        ])
        append_files(output, files)
    if missing:
        raise ValueError("Missing source license text for: " + ", ".join(missing))
    key = f"rust-std@{toolchain}"
    entry = index.get("distribution_notices", {}).get(key)
    if entry is None:
        raise ValueError(f"Missing toolchain notices: {key}")
    if entry.get("commit") != toolchain_commit:
        raise ValueError(f"Toolchain notice commit mismatch: {key}")
    output.extend([key, f'Declared license: {entry["license"]}'])
    append_files(output, indexed_files(supplement_root, entry, "toolchain-distribution"))
    return "\n".join(output) + "\n"


def main():
    parser = argparse.ArgumentParser(description="Collect license texts from the locked Cargo dependency graph")
    parser.add_argument("--manifest-path", default="Cargo.toml")
    parser.add_argument("--output", required=True)
    parser.add_argument("--target")
    arguments = parser.parse_args()
    compiler = dict(line.split(": ", 1) for line in subprocess.check_output(
        ["rustc", "-vV"], encoding="utf-8").splitlines() if ": " in line)
    target = arguments.target or compiler["host"]
    metadata = json.loads(subprocess.check_output([
        "cargo", "metadata", "--locked", "--format-version", "1",
        "--filter-platform", target,
        "--manifest-path", arguments.manifest_path,
    ]))
    root = Path(metadata["workspace_root"])
    lock = tomllib.loads((root / "Cargo.lock").read_text(encoding="utf-8"))
    notices = generate(metadata, root / "licenses" / "third-party", lock["package"],
                       compiler["release"], compiler["commit-hash"])
    destination = Path(arguments.output).resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="", dir=destination.parent, delete=False) as temporary:
        temporary.write(notices)
        temporary_path = Path(temporary.name)
    temporary_path.replace(destination)


if __name__ == "__main__":
    main()
