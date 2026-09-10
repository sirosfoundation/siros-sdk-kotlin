#!/usr/bin/env python3
"""Complete a hand-rolled POM with the elements Maven Central requires.

Usage: complete-pom.py <source.pom> <dest.pom>

Reads POM_NAME, POM_DESCRIPTION, POM_URL, LICENSE_NAME, LICENSE_URL from
the environment. Elements the POM already has are kept; only missing ones
(or ones with empty text) are filled in.
"""
import os
import sys
import xml.etree.ElementTree as ET

NS = "http://maven.apache.org/POM/4.0.0"


def q(tag: str) -> str:
    return f"{{{NS}}}{tag}"


def ensure(parent: ET.Element, tag: str, text: str | None = None) -> ET.Element:
    el = parent.find(q(tag))
    if el is None:
        el = ET.SubElement(parent, q(tag))
    if text is not None and not (el.text or "").strip():
        el.text = text
    return el


def main() -> None:
    src, dst = sys.argv[1], sys.argv[2]
    ET.register_namespace("", NS)
    tree = ET.parse(src)
    root = tree.getroot()
    url = os.environ["POM_URL"]
    repo_path = url.split("github.com/", 1)[1].rstrip("/")

    ensure(root, "name", os.environ["POM_NAME"])
    ensure(root, "description", os.environ["POM_DESCRIPTION"])
    ensure(root, "url", url)

    lic = ensure(ensure(root, "licenses"), "license")
    ensure(lic, "name", os.environ["LICENSE_NAME"])
    ensure(lic, "url", os.environ["LICENSE_URL"])

    dev = ensure(ensure(root, "developers"), "developer")
    ensure(dev, "id", "sirosfoundation")
    ensure(dev, "name", "SIROS Foundation")
    ensure(dev, "url", "https://siros.org")

    scm = ensure(root, "scm")
    ensure(scm, "url", url)
    ensure(scm, "connection", f"scm:git:{url}.git")
    ensure(scm, "developerConnection", f"scm:git:ssh://git@github.com/{repo_path}.git")

    ET.indent(tree, space="  ")
    tree.write(dst, encoding="UTF-8", xml_declaration=True)


if __name__ == "__main__":
    main()
