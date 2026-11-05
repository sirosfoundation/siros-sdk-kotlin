#!/usr/bin/env python3
"""Generate and verify target-filtered third-party license inventories."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess


def metadata(target: str, manifest_path: Path) -> dict:
    output = subprocess.check_output(
        [
            "cargo",
            "metadata",
            "--format-version",
            "1",
            "--filter-platform",
            target,
            "--locked",
            "--manifest-path",
            str(manifest_path),
        ],
        text=True,
    )
    return json.loads(output)


def normal_package_versions(document: dict) -> set[tuple[str, str]]:
    """Return non-root packages reachable through normal, non-build/dev edges."""
    packages = {package["id"]: package for package in document["packages"]}
    nodes = {node["id"]: node for node in document["resolve"]["nodes"]}
    root_id = document["resolve"]["root"]
    if root_id is None:
        raise RuntimeError("license inventory requires a concrete root package")

    reachable: set[str] = set()
    pending = [root_id]
    while pending:
        package_id = pending.pop()
        if package_id in reachable:
            continue
        reachable.add(package_id)
        for dependency in nodes[package_id]["deps"]:
            if any(kind["kind"] is None for kind in dependency["dep_kinds"]):
                pending.append(dependency["pkg"])

    return {
        (package["name"], package["version"])
        for package_id, package in packages.items()
        if package_id in reachable and package_id != root_id
    }


def expected_package_versions(target: str, manifest_path: Path) -> set[tuple[str, str]]:
    return normal_package_versions(metadata(target, manifest_path))


def inventory_package_versions(inventory: dict) -> set[tuple[str, str]]:
    packages = [
        (package["package_name"], package["package_version"])
        for package in inventory["third_party_libraries"]
    ]
    if len(packages) != len(set(packages)):
        raise RuntimeError("license inventory contains duplicate package/version entries")
    return set(packages)


def require_exact_inventory(inventory: dict, expected: set[tuple[str, str]], target: str) -> None:
    actual = inventory_package_versions(inventory)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise RuntimeError(f"inventory mismatch for {target}: missing={missing}, extra={extra}")


def generate(target: str, output: Path, manifest_path: Path) -> None:
    manifest_path = manifest_path.resolve()
    result = subprocess.run(
        ["cargo", "bundle-licenses", "--format", "json", "--output", "-"],
        cwd=manifest_path.parent,
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    )
    inventory = json.loads(result.stdout)
    expected = expected_package_versions(target, manifest_path)
    inventory["third_party_libraries"] = [
        package
        for package in inventory["third_party_libraries"]
        if (package["package_name"], package["package_version"]) in expected
    ]
    inventory["third_party_libraries"].sort(
        key=lambda package: (package["package_name"], package["package_version"])
    )
    require_exact_inventory(inventory, expected, target)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(inventory, ensure_ascii=False, indent=2, sort_keys=True) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--manifest-path", type=Path, default=Path("Cargo.toml"))
    args = parser.parse_args()
    generate(args.target, args.output, args.manifest_path)


if __name__ == "__main__":
    main()
