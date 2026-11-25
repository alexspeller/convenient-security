#!/usr/bin/env python3
"""Read-only release watch: unchecked Claude images need an audit session.

The installed daemon supplies both the catalog and exec-bound live identities.
Never execute a candidate Claude binary, inspect its login files, mutate the
catalog, or interpret version labels as authorization in this cheap check.
"""

import json
import re
import subprocess
import urllib.request

LATEST_RELEASE_URL = ("https://storage.googleapis.com/claude-code-dist-86c565f3-f756-42ad-8dfa-d59b1c096819/"
                      "claude-code-releases/latest")


def evaluate(report, latest_release=None):
    if not isinstance(report, dict) or report.get("schemaVersion") != 1:
        raise ValueError("Claude release inventory is unavailable or unsupported")
    builds, unreadable, releases = report.get("builds"), report.get("unreadablePaths"), report.get("checkedReleases")
    if not isinstance(builds, list) or len(builds) > 64 or not isinstance(unreadable, list) or len(unreadable) > 64:
        raise ValueError("invalid Claude release inventory")
    if not isinstance(releases, list) or len(releases) > 1024 or any(
            not isinstance(v, str) or not 0 < len(v.encode()) <= 64
            or any(ord(c) < 32 or ord(c) == 127 for c in v) for v in releases):
        raise ValueError("invalid checked release list")
    images = {}
    for build in builds:
        if not isinstance(build, dict):
            raise ValueError("invalid Claude image")
        path, label = build.get("path"), build.get("versionLabel")
        cdhash, checked = build.get("cdHash"), build.get("checkedVersion")
        if (not isinstance(path, str) or not path.startswith("/") or len(path.encode()) > 1024
                or not isinstance(label, str) or not 0 < len(label.encode()) <= 64
                or any(ord(c) < 32 or ord(c) == 127 for c in path + label)
                or type(build.get("running")) is not bool
                or (cdhash is not None and (not isinstance(cdhash, str) or not re.fullmatch(r"[0-9a-f]{40}", cdhash)))
                or (checked is not None and (cdhash is None or not isinstance(checked, str)
                                             or not 0 < len(checked.encode()) <= 64))):
            raise ValueError("invalid Claude image metadata")
        if checked is None:
            # A copied image or a live process with a replaced path is one
            # audit, keyed by its real code identity. Paths remain display data.
            key = cdhash or path
            item = {"cdHash": cdhash, "path": path, "versionLabel": label}
            if key not in images or path < images[key]["path"]:
                images[key] = item
    upstream = latest_release if latest_release is not None and latest_release not in releases else None
    if latest_release is not None and not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", latest_release):
        raise ValueError("invalid upstream release label")
    if images or upstream:
        keys = sorted(images)
        # Bound the payload below the runner's 16 KiB limit. Subsequent checks
        # expose any remaining images as checked builds leave this set.
        return {"status": "trip", "payload": {"uncheckedImages": [images[k] for k in keys[:8]],
                                                "additionalImages": max(0, len(keys) - 8),
                                                "upstreamRelease": upstream}}
    if unreadable:
        raise ValueError("Claude build inventory is incomplete")
    return {"status": "clear"}


def check():
    try:
        result = subprocess.run(
            ["/Applications/ConvenientSecurity.app/Contents/MacOS/csec", "status", "--claude-builds-json"],
            capture_output=True, timeout=25, check=True,
        )
        if len(result.stdout) > 256 * 1024:
            raise ValueError("Claude release inventory exceeds its bound")
        report = json.loads(result.stdout)
        local = evaluate(report)
        try:
            with urllib.request.urlopen(LATEST_RELEASE_URL, timeout=10) as response:
                latest = response.read(128).decode("ascii").strip()
            return evaluate(report, latest)
        except (OSError, ValueError):
            # A failed upstream lookup cannot hide known unchecked local images.
            if local["status"] == "trip":
                return local
            raise ValueError("could not read the official latest Claude release") from None
    except (OSError, subprocess.SubprocessError, ValueError) as error:
        # Do not copy arbitrary CLI output, argv or environment into a report.
        return {"status": "error", "error": str(error)[:240]}


if __name__ == "__main__":
    print(json.dumps(check(), sort_keys=True))
