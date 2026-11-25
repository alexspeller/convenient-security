#!/usr/bin/env python3
"""Prepare and check csec's signed release manifest (docs/release-manifest.md).

  bin/release-manifest.py write --download URL [--previous manifest.json] OUTPUT
      Write the next manifest for this checkout's release: VERSION and the
      build number (the commit count of HEAD), the download page, and a
      sequence one above the previous manifest's. Every other section of the
      previous manifest (the audited Claude Code list, say) is carried over
      unchanged. Nothing is signed here.

  bin/release-manifest.py claude [--previous manifest.json] OUTPUT
      Write the next manifest with this checkout's audited Claude Code list
      (ClaudeBuildVerification.shipped in
      agent/Sources/ConvenientSecurity/ClaudeBuildVerification.swift) as its
      `claude_code` section, so csec releases built before an audit admit
      that image too. Everything else, the announced release included, is
      carried over from the previous manifest unchanged. Nothing is signed here.

  bin/release-manifest.py verify manifest.json manifest.json.sig
      Check a signed manifest the way csec does, with stock OpenSSH: the
      signature must come from a key pinned in this checkout
      (ReleaseSigningKeys in agent/Sources/ConvenientSecurity/ReleaseManifest.swift)
      for the manifest namespace, and the manifest must parse as schema 1.

The private key never comes near this tool: whoever holds it signs the
written file as `ssh-keygen -Y sign -n release-manifest@convenientsecurity.app`
would.
"""

import argparse
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NAMESPACE = "release-manifest@convenientsecurity.app"
PRINCIPAL = "csec-release"
PINNED_SOURCE = ROOT / "agent/Sources/ConvenientSecurity/ReleaseManifest.swift"
CATALOG_SOURCE = ROOT / "agent/Sources/ConvenientSecurity/ClaudeBuildVerification.swift"
CDHASH = re.compile(r"^[0-9a-f]{40}$")
# ReleaseManifest.ClaudeCodeBuild.isVersionLabel: ClaudeBuildSummary.maximumVersionLabelBytes is 64.
CLAUDE_VERSION = re.compile(r"^[A-Za-z0-9.+_-]{1,64}$")
MAXIMUM_CLAUDE_BUILDS = 1024
RELEASE_VERSION = re.compile(r"^(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})$")


def fail(message):
    print(f"release-manifest: {message}", file=sys.stderr)
    sys.exit(1)


def pinned_keys(source=PINNED_SOURCE):
    """The `ssh-ed25519 …` lines inside ReleaseSigningKeys.pinned."""
    text = source.read_text()
    match = re.search(r"public static let pinned: \[String\] = \[(.*?)\]", text, re.S)
    if not match:
        fail(f"could not find ReleaseSigningKeys.pinned in {source}")
    return re.findall(r'"(ssh-ed25519 [A-Za-z0-9+/=]+(?: [^"]*)?)"', match.group(1))


def compiled_claude_builds(source=CATALOG_SOURCE):
    """The `Record(cdHash:version:)` entries of ClaudeBuildVerification.shipped, in order."""
    text = source.read_text()
    match = re.search(r"public static let shipped = ClaudeBuildVerification\(records: \[(.*?)\n    \]\)", text, re.S)
    if not match:
        fail(f"could not find ClaudeBuildVerification.shipped in {source}")
    builds = [{"cdhash": cdhash, "version": version} for cdhash, version in
              re.findall(r'cdHash: "([^"]*)", version: "([^"]*)"', match.group(1))]
    if len(builds) != match.group(1).count("Record("):
        fail(f"could not read every record of ClaudeBuildVerification.shipped in {source}")
    return builds


def release_version(root=ROOT):
    version = (root / "VERSION").read_text().strip()
    if not RELEASE_VERSION.match(version):
        fail(f"VERSION must be MAJOR.MINOR.PATCH, not {version!r}")
    return version


def build_number(root=ROOT):
    shallow = subprocess.run(["git", "-C", str(root), "rev-parse", "--is-shallow-repository"],
                             check=True, text=True, stdout=subprocess.PIPE).stdout.strip()
    if shallow != "false":
        fail("this is a shallow clone; its commit count is not the build number")
    count = subprocess.run(["git", "-C", str(root), "rev-list", "--count", "HEAD"],
                           check=True, text=True, stdout=subprocess.PIPE).stdout.strip()
    return int(count)


def check_manifest(document):
    """The same rules csec applies to schema 1 (ReleaseManifest.parse)."""
    if not isinstance(document, dict):
        fail("the manifest is not a JSON object")
    if type(document.get("schema")) is not int or document["schema"] != 1:
        fail("the manifest's schema must be 1")
    if type(document.get("sequence")) is not int or document["sequence"] < 1:
        fail("the manifest's sequence must be a positive integer")
    check_claude_code(document.get("claude_code"))
    release = document.get("release")
    if release is None:
        return
    if not isinstance(release, dict):
        fail("the manifest's release must be an object")
    if not isinstance(release.get("version"), str) or not RELEASE_VERSION.match(release["version"]):
        fail("the release version must be MAJOR.MINOR.PATCH")
    if type(release.get("build")) is not int or release["build"] < 1:
        fail("the release build must be a positive integer")
    check_download(release.get("download"))


def check_claude_code(section):
    """ReleaseManifest.claudeCode: one bad entry refuses the whole manifest."""
    if section is None:
        return
    if not isinstance(section, dict) or not isinstance(section.get("checked"), list):
        fail("the manifest's claude_code must be an object with a checked list")
    if len(section["checked"]) > MAXIMUM_CLAUDE_BUILDS:
        fail(f"the manifest's claude_code lists more than {MAXIMUM_CLAUDE_BUILDS} images")
    seen = set()
    for build in section["checked"]:
        if not isinstance(build, dict) or not isinstance(build.get("cdhash"), str) \
                or not CDHASH.match(build["cdhash"]) or build["cdhash"] in seen:
            fail("each claude_code image needs its own 40-character lowercase hex cdhash")
        if not isinstance(build.get("version"), str) or not CLAUDE_VERSION.match(build["version"]):
            fail("each claude_code version must be 1 to 64 letters, digits or . + _ -")
        seen.add(build["cdhash"])


def check_download(download):
    if not isinstance(download, str) or not re.match(r"^https://[^/\s]+[\x21-\x7e]*$", download) \
            or len(download) > 200:
        fail("the download address must be an https URL of printable ASCII, at most 200 characters")


def write(arguments):
    check_download(arguments.download)
    previous = {}
    if arguments.previous:
        previous = json.loads(Path(arguments.previous).read_text())
        check_manifest(previous)
    document = dict(previous)
    document["schema"] = 1
    document["sequence"] = previous.get("sequence", 0) + 1
    document["release"] = {
        "version": release_version(),
        "build": build_number(),
        "download": arguments.download,
    }
    check_manifest(document)
    old = previous.get("release")
    if old:
        key = lambda release: (tuple(int(part) for part in release["version"].split(".")), release["build"])
        if key(document["release"]) < key(old):
            fail(f"this checkout ({document['release']['version']}, build {document['release']['build']}) "
                 f"is older than the release the previous manifest announces "
                 f"({old['version']}, build {old['build']})")
    Path(arguments.output).write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    print(f"wrote {arguments.output}: sequence {document['sequence']}, "
          f"csec {document['release']['version']} (build {document['release']['build']})")


def claude(arguments, source=CATALOG_SOURCE):
    previous = {}
    if arguments.previous:
        previous = json.loads(Path(arguments.previous).read_text())
        check_manifest(previous)
    document = dict(previous)
    document["schema"] = 1
    document["sequence"] = previous.get("sequence", 0) + 1
    builds = compiled_claude_builds(source)
    document["claude_code"] = {"checked": builds}
    check_manifest(document)
    before = {build["cdhash"] for build in (previous.get("claude_code") or {}).get("checked", [])}
    after = {build["cdhash"] for build in builds}
    Path(arguments.output).write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    print(f"wrote {arguments.output}: sequence {document['sequence']}, {len(builds)} Claude Code images "
          f"({len(after - before)} added, {len(before - after)} removed)")


def verify(arguments, keys=None):
    keys = pinned_keys() if keys is None else keys
    if not keys:
        fail("this checkout pins no release signing key (ReleaseSigningKeys.pinned is empty)")
    manifest = Path(arguments.manifest).read_bytes()
    with tempfile.TemporaryDirectory() as directory:
        allowed = Path(directory) / "allowed_signers"
        allowed.write_text("".join(f'{PRINCIPAL} namespaces="{NAMESPACE}" {key}\n' for key in keys))
        result = subprocess.run(
            ["ssh-keygen", "-Y", "verify", "-f", str(allowed), "-I", PRINCIPAL, "-n", NAMESPACE,
             "-s", arguments.signature],
            input=manifest, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if result.returncode != 0:
        fail("the signature does not verify against a pinned release key: "
             + result.stdout.decode(errors="replace").strip())
    try:
        document = json.loads(manifest)
    except ValueError:
        fail("the manifest is not JSON")
    check_manifest(document)
    release = document.get("release") or {}
    claude_builds = (document.get("claude_code") or {}).get("checked", [])
    print(f"verified: sequence {document['sequence']}"
          + (f", csec {release['version']} (build {release['build']})" if release else ", no release")
          + f", {len(claude_builds)} Claude Code images")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    write_parser = commands.add_parser("write")
    write_parser.add_argument("--download", required=True)
    write_parser.add_argument("--previous")
    write_parser.add_argument("output")
    claude_parser = commands.add_parser("claude")
    claude_parser.add_argument("--previous")
    claude_parser.add_argument("output")
    verify_parser = commands.add_parser("verify")
    verify_parser.add_argument("manifest")
    verify_parser.add_argument("signature")
    arguments = parser.parse_args(argv)
    if arguments.command == "write":
        write(arguments)
    elif arguments.command == "claude":
        claude(arguments)
    else:
        verify(arguments)


if __name__ == "__main__":
    main()
