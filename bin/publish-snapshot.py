#!/usr/bin/env python3
"""Publish one commit's tree to a public repository as a single new commit.

Development stays in a private repository. The public repository's main gets
one commit per publish, whose tree is the source commit's tree without the
paths .gitattributes marks export-ignore, whose parent is the public main and
whose message names no private commit. Nothing private is reachable from it,
so pushing it uploads no private history.

Before building the commit, the exact tree it would publish is exported and
checked; any finding refuses the publish:
- gitleaks (`dir`, values redacted), with publish/.gitleaksignore from the
  source commit holding the fingerprints of reviewed findings;
- the source commit's publish/terms: case-insensitive fixed strings, one per
  line (`#` starts a comment), that must appear in no published file.
Findings are reported as path, line and rule or term only.

--check runs the checks alone and needs no public remote. Without --push it
stops after building the snapshot and prints what it would publish.
"""

import argparse
import datetime
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile

TERMS = "publish/terms"
LEAKS_IGNORE = "publish/.gitleaksignore"
NOREPLY = "@users.noreply.github.com"


class Refused(Exception):
    pass


def git(*args, env=None, input=None):
    done = subprocess.run(["git", *args], capture_output=True, env=env, input=input)
    if done.returncode != 0:
        raise Refused(f"git {' '.join(args)} failed: {done.stderr.decode(errors='replace').strip()}")
    return done.stdout


def git_text(*args, env=None):
    return git(*args, env=env).decode().strip()


def tracked_file(commit, path):
    done = subprocess.run(["git", "cat-file", "blob", f"{commit}:{path}"], capture_output=True)
    return done.stdout if done.returncode == 0 else None


def archive_names(treeish):
    with tempfile.TemporaryFile() as tar:
        subprocess.run(["git", "archive", "--format=tar", treeish], stdout=tar, check=True)
        tar.seek(0)
        with tarfile.open(fileobj=tar) as archive:
            return {m.name for m in archive.getmembers() if not m.isdir()}


def export(treeish, into):
    with tempfile.TemporaryFile() as tar:
        subprocess.run(["git", "archive", "--format=tar", treeish], stdout=tar, check=True)
        tar.seek(0)
        with tarfile.open(fileobj=tar) as archive:
            # The archive is git's own output for a local tree; the filter,
            # where this Python has one, only refuses what git never writes.
            if hasattr(tarfile, "tar_filter"):
                archive.extractall(into, filter="tar")
            else:
                archive.extractall(into)


def public_tree(commit):
    """The source tree without its export-ignore paths, as a tree object."""
    everything = set(git(
        "ls-tree", "-r", "-z", "--name-only", "--full-tree", commit).decode().split("\0")) - {""}
    published = archive_names(commit)
    unexpected = published - everything
    if unexpected:
        raise Refused(f"git archive produced paths the commit does not track: {sorted(unexpected)[:5]}")
    left_out = sorted(everything - published)
    with tempfile.TemporaryDirectory() as scratch:
        env = {**os.environ, "GIT_INDEX_FILE": str(Path(scratch) / "index")}
        git("read-tree", commit, env=env)
        if left_out:
            git("update-index", "--force-remove", "-z", "--stdin", env=env,
                input="".join(f"{path}\0" for path in left_out).encode())
        tree = git_text("write-tree", env=env)
    if archive_names(tree) != published:
        raise Refused("the built tree does not hold exactly the exported files")
    return tree, published, left_out


def term_findings(root, terms):
    lowered = [(term, term.lower().encode()) for term in terms]
    found = []
    for path in sorted(p for p in Path(root).rglob("*") if p.is_symlink() or p.is_file()):
        relative = path.relative_to(root).as_posix()
        content = os.readlink(path).encode() if path.is_symlink() else path.read_bytes()
        for number, line in enumerate(content.lower().split(b"\n"), 1):
            for term, needle in lowered:
                if needle in line:
                    found.append(f"{relative}:{number}: {term}")
        for term, needle in lowered:
            if needle in relative.lower().encode():
                found.append(f"{relative}: path contains {term}")
    return found


def leak_findings(root, ignore, scratch):
    # gitleaks also reads a .gitleaks.toml or .gitleaksignore at the root it
    # scans and allows lines marked gitleaks:allow, so published files could
    # quietly narrow the scan: only the private publish/ configuration counts.
    for own in (".gitleaks.toml", ".gitleaksignore"):
        if (Path(root) / own).exists():
            raise Refused(f"the published tree has a {own}; keep scanner configuration in publish/")
    gitleaks = os.environ.get("CSEC_GITLEAKS", "gitleaks")
    report = Path(scratch) / "gitleaks.json"
    ignore_dir = Path(scratch) / "ignore"
    ignore_dir.mkdir()
    (ignore_dir / ".gitleaksignore").write_bytes(ignore or b"")
    try:
        done = subprocess.run(
            [gitleaks, "dir", ".", "--redact=100", "--no-banner", "--log-level", "error",
             "--exit-code", "1", "--ignore-gitleaks-allow", "--gitleaks-ignore-path", str(ignore_dir),
             "--report-format", "json", "--report-path", str(report)],
            cwd=root, capture_output=True,
            env={k: v for k, v in os.environ.items() if not k.startswith("GITLEAKS_CONFIG")})
    except FileNotFoundError:
        raise Refused(f"gitleaks not found ({gitleaks}); install it or set CSEC_GITLEAKS")
    if done.returncode not in (0, 1) or not report.is_file():
        raise Refused(f"gitleaks did not finish (exit {done.returncode})")
    findings = json.loads(report.read_text() or "[]")
    if done.returncode == 1 and not findings:
        raise Refused("gitleaks exited 1 without a report of its findings")
    return [f"{f.get('File')}:{f.get('StartLine')}: {f.get('RuleID')} ({f.get('Fingerprint')})"
            for f in findings]


def identity():
    name = git_text("config", "user.name")
    email = git_text("config", "user.email")
    if not email.endswith(NOREPLY):
        raise Refused(f"user.email must be a GitHub noreply address (…{NOREPLY}) so the public commit "
                      "carries no personal address")
    return name, email


def remote_main(remote):
    line = git_text("ls-remote", remote, "refs/heads/main")
    if not line:
        return None
    parent = line.split()[0]
    git("fetch", "--quiet", "--no-tags", remote, "refs/heads/main")
    return parent


def check_remote(remote):
    url = git_text("remote", "get-url", remote)
    for other in git_text("remote").split():
        if other != remote and git_text("remote", "get-url", other) == url:
            raise Refused(f"remote {remote} has the same URL as {other}; the public remote must be its own repository")
    return url


def publish(source, remote, push, out, check_only=False):
    commit = git_text("rev-parse", "--verify", f"{source}^{{commit}}")
    url = None if check_only else check_remote(remote)
    terms_file = tracked_file(commit, TERMS)
    if terms_file is None:
        raise Refused(f"{source} has no {TERMS}")
    terms = [line.strip() for line in terms_file.decode().splitlines()
             if line.strip() and not line.strip().startswith("#")]
    if not terms:
        raise Refused(f"{TERMS} lists no terms")
    tree, published, left_out = public_tree(commit)
    if any(path == "publish" or path.startswith("publish/") for path in published):
        raise Refused("publish/ would be published: .gitattributes must mark it export-ignore")
    with tempfile.TemporaryDirectory() as scratch:
        root = Path(scratch) / "tree"
        root.mkdir()
        export(tree, root)
        findings = term_findings(root, terms)
        findings += leak_findings(root, tracked_file(commit, LEAKS_IGNORE), scratch)
    if findings:
        raise Refused(f"{len(findings)} finding(s) in the tree of {commit[:12]}; nothing published:\n"
                      + "\n".join(f"  {f}" for f in findings))
    if check_only:
        print(f"source {commit[:12]}: {len(published)} files, {len(left_out)} left out; checks clean", file=out)
        return None
    name, email = identity()
    parent = remote_main(remote)
    if parent and git_text("rev-parse", f"{parent}^{{tree}}") == tree:
        print(f"{remote} main {parent[:12]} already has this tree; nothing to publish", file=out)
        return None
    when = datetime.datetime.now(datetime.timezone.utc)
    env = {**os.environ, "GIT_AUTHOR_NAME": name, "GIT_AUTHOR_EMAIL": email,
           "GIT_COMMITTER_NAME": name, "GIT_COMMITTER_EMAIL": email,
           "GIT_AUTHOR_DATE": when.isoformat(), "GIT_COMMITTER_DATE": when.isoformat()}
    snapshot = git_text("commit-tree", tree, *(["-p", parent] if parent else []),
                        "-m", f"Snapshot {when:%Y-%m-%d}", env=env)
    print(f"source {commit[:12]}: {len(published)} files, {len(left_out)} left out "
          f"({', '.join(left_out[:5])}{', …' if len(left_out) > 5 else ''}); "
          f"checks clean; snapshot {snapshot[:12]} on {'parent ' + parent[:12] if parent else 'no parent'}",
          file=out)
    if not push:
        print(f"dry run: would push {snapshot[:12]} to {remote} ({url}) main; --push publishes it", file=out)
        return snapshot
    git("push", "--quiet", remote, f"{snapshot}:refs/heads/main")
    print(f"published {snapshot[:12]} to {remote} main", file=out)
    return snapshot


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--source", default="main", help="commit to publish (default: main)")
    parser.add_argument("--remote", default="public", help="the public repository's remote (default: public)")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="run the checks only; no remote needed")
    mode.add_argument("--push", action="store_true", help="push the snapshot; without it, a dry run")
    args = parser.parse_args(argv)
    try:
        publish(args.source, args.remote, args.push, sys.stdout, check_only=args.check)
    except Refused as refusal:
        print(f"publish-snapshot: refused: {refusal}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
