#!/usr/bin/env python3
"""Validate the packaged AAR notices and Maven metadata for nymauth artifacts."""

import json
from pathlib import Path
import sys
import xml.etree.ElementTree as ET
import zipfile

from license_inventory import expected_package_versions, inventory_package_versions


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"artifact validation failed: {message}")


def main() -> None:
    if len(sys.argv) != 5:
        raise SystemExit("usage: validate-artifact.py <aar> <pom> <artifact-id> <version>")

    aar_path = Path(sys.argv[1])
    pom_path = Path(sys.argv[2])
    artifact_id = sys.argv[3]
    version = sys.argv[4]
    crate_root = Path(__file__).resolve().parents[1]
    repo_root = crate_root.parents[1]

    is_demo = artifact_id == "nymauth-demo-issuer"
    notice_source = crate_root / ("demo-issuer/NOTICE" if is_demo else "NOTICE")
    manifest_path = crate_root / ("demo-issuer/Cargo.toml" if is_demo else "Cargo.toml")
    notice_text = " ".join(notice_source.read_text().split())
    require("UniFFI 0.29.5" in notice_text, "NOTICE does not identify the UniFFI version")
    require("Mozilla Public License 2.0" in notice_text, "NOTICE does not identify the UniFFI license")
    require(
        "https://github.com/mozilla/uniffi-rs/tree/v0.29.5" in notice_text,
        "NOTICE does not identify the corresponding UniFFI source",
    )
    expected_description = (
        "Native nymauth BBS demo issuer for the SIROS SDKs"
        if artifact_id == "nymauth-demo-issuer"
        else "Native nymauth provers for the SIROS SDKs"
    )
    expected_files = {
        "LICENSE": repo_root / "LICENSE",
        "NOTICE": notice_source,
        "licenses/longfellow-zk.LICENSE": crate_root / "licenses/longfellow-zk.LICENSE",
        "licenses/bbs-cd-plugins.LICENSE": crate_root / "licenses/bbs-cd-plugins.LICENSE",
        "licenses/bbs-cd-plugins-THIRD_PARTY_NOTICES.md": crate_root / "licenses/bbs-cd-plugins-THIRD_PARTY_NOTICES.md",
        "licenses/uniffi-0.29.5-MPL-2.0.LICENSE": crate_root / "licenses/uniffi-0.29.5-MPL-2.0.LICENSE",
        "licenses/sha2-asm-0.6.4.LICENSE": crate_root / "licenses/sha2-asm-0.6.4.LICENSE",
        "licenses/zstd-0.13.3.LICENSE": crate_root / "licenses/zstd-0.13.3.LICENSE",
        "licenses/zstd-sys-2.1.2.LICENSE": crate_root / "licenses/zstd-sys-2.1.2.LICENSE",
        "licenses/zstd-1.5.7-BSD-3-Clause.LICENSE": crate_root / "licenses/zstd-1.5.7-BSD-3-Clause.LICENSE",
        "licenses/zstd-safe-7.3.0.LICENSE": crate_root / "licenses/zstd-safe-7.3.0.LICENSE",
        "licenses/subtle-2.6.1.LICENSE": crate_root / "licenses/subtle-2.6.1.LICENSE",
    }
    require(aar_path.is_file(), f"missing {aar_path}")
    require(pom_path.is_file(), f"missing {pom_path}")

    with zipfile.ZipFile(aar_path) as aar:
        names = set(aar.namelist())
        for name, source in expected_files.items():
            require(name in names, f"{name} is absent from {aar_path.name}")
            require(aar.read(name) == source.read_bytes(), f"{name} differs from {source}")
        require("AndroidManifest.xml" in names, "AndroidManifest.xml is absent")
        require("classes.jar" in names, "classes.jar is absent")

        targets = ["aarch64-linux-android"]
        if any(name.startswith("jni/x86_64/") for name in names):
            targets.append("x86_64-linux-android")
        required_packages = {("uniffi", "0.29.5")}
        if artifact_id == "nymauth-native":
            required_packages.update(
                {
                    ("sha2-asm", "0.6.4"),
                    ("zstd", "0.13.3"),
                    ("zstd-sys", "2.1.2+zstd.1.5.7"),
                    ("zstd-safe", "7.3.0"),
                    ("subtle", "2.6.1"),
                }
            )
        for target in targets:
            inventory_name = f"licenses/THIRD_PARTY_LICENSES-{target}.json"
            require(inventory_name in names, f"{inventory_name} is absent")
            inventory = json.loads(aar.read(inventory_name))
            require(inventory.get("root_name") == artifact_id, f"wrong root package in {inventory_name}")
            try:
                packages = inventory_package_versions(inventory)
            except (KeyError, RuntimeError) as error:
                raise SystemExit(f"artifact validation failed: invalid {inventory_name}: {error}") from error
            expected = expected_package_versions(target, manifest_path)
            missing = expected - packages
            extra = packages - expected
            require(
                packages == expected,
                f"{inventory_name} differs from filtered Cargo metadata: "
                f"missing={sorted(missing)}, extra={sorted(extra)}",
            )
            missing_notices = required_packages - packages
            require(not missing_notices, f"{inventory_name} is missing noticed packages: {sorted(missing_notices)}")
            uniffi = next(
                package
                for package in inventory["third_party_libraries"]
                if package["package_name"] == "uniffi"
            )
            require(uniffi["license"] == "MPL-2.0", f"wrong UniFFI license in {inventory_name}")

    namespace = {"m": "http://maven.apache.org/POM/4.0.0"}
    pom = ET.parse(pom_path).getroot()
    expected_text = {
        "modelVersion": "4.0.0",
        "groupId": "org.siros",
        "artifactId": artifact_id,
        "version": version,
        "packaging": "aar",
        "name": artifact_id,
        "description": expected_description,
        "url": "https://github.com/sirosfoundation/siros-sdk-kotlin",
        "licenses/license/name": "BSD 2-Clause License",
        "licenses/license/url": "https://opensource.org/license/bsd-2-clause",
        "licenses/license/distribution": "repo",
        "developers/developer/organization": "SIROS Foundation",
        "developers/developer/organizationUrl": "https://siros.org",
        "scm/url": "https://github.com/sirosfoundation/siros-sdk-kotlin",
        "scm/connection": "scm:git:https://github.com/sirosfoundation/siros-sdk-kotlin.git",
        "scm/developerConnection": "scm:git:ssh://git@github.com/sirosfoundation/siros-sdk-kotlin.git",
    }
    for path, expected in expected_text.items():
        namespaced_path = "/".join(f"m:{part}" for part in path.split("/"))
        actual = pom.findtext(namespaced_path, namespaces=namespace)
        require(actual == expected, f"POM {path} is {actual!r}, expected {expected!r}")

    jna = pom.find("m:dependencies/m:dependency", namespace)
    require(jna is not None, "POM has no JNA dependency")
    require(jna.findtext("m:groupId", namespaces=namespace) == "net.java.dev.jna", "unexpected JNA groupId")
    require(jna.findtext("m:artifactId", namespaces=namespace) == "jna", "unexpected JNA artifactId")
    require(jna.findtext("m:version", namespaces=namespace) == "5.14.0", "unexpected JNA version")
    require(jna.findtext("m:type", namespaces=namespace) == "aar", "unexpected JNA type")
    print(f"validated {aar_path.name} and {pom_path.name}")


if __name__ == "__main__":
    main()
