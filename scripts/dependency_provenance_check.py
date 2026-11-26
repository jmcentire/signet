#!/usr/bin/env python3
"""Check Cargo.lock for compromised or suspect dependencies.

Two scopes:

Every registry package in Cargo.lock is looked up, at its exact version, in OSV
(which aggregates the RustSec database, GitHub advisories and the OpenSSF
malicious-packages list). Every crate name is also looked up for a
malicious-package record at any version.

Packages added or changed relative to a base git ref (default origin/main) get
the closer look that lists cannot give a release nobody has examined yet:

  - not yanked;
  - registry checksum and locally cached archive both match Cargo.lock;
  - at least --min-age-days old, unless listed in dependency_age_exceptions.json
    with a reason;
  - every published file is identical to the public source repository at the
    commit the package records, and that commit is one the registry recorded
    from the repository's own CI, or is on a branch or tag of that repository.
    A release that fails this and was then examined by hand is listed, with
    what was found, in dependency_provenance_reviewed.json;
  - build scripts and proc-macros (code that runs at build time) are listed.

This cannot prove a dependency is safe. It shows that none is on a public list,
that what was published is what is in the public repository, and that nothing
is too new for anyone to have noticed a problem.

Needs network access to crates.io, api.osv.dev and github.com, and a populated
cargo cache (`cargo fetch --locked`). Not part of `make check`.

    python3 -B scripts/dependency_provenance_check.py [--base REF] [--min-age-days N] [--all]

Exit status 0 when nothing needs attention, 1 otherwise.
"""

from __future__ import annotations

import argparse
import datetime
import glob
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
AGENT = {"User-Agent": "dependency-provenance-check"}
SKIP = {".cargo_vcs_info.json", ".cargo-ok", "Cargo.lock", "Cargo.toml"}
PACKAGE = re.compile(
    r'\[\[package\]\]\nname = "([^"]+)"\nversion = "([^"]+)"\n'
    r'(?:source = "([^"]+)"\n)?(?:checksum = "([^"]+)"\n)?'
)


def packages(text: str) -> dict[tuple[str, str], tuple[str | None, str | None]]:
    return {(m[1], m[2]): (m[3], m[4]) for m in PACKAGE.finditer(text)}


def fetch_json(url: str, body: dict | None = None) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    headers = dict(AGENT, **({"Content-Type": "application/json"} if body is not None else {}))
    for attempt in range(3):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, data=data, headers=headers), timeout=60) as reply:
                return json.load(reply)
        except Exception:  # noqa: BLE001 - retried, then reported by the caller
            if attempt == 2:
                raise
            time.sleep(3)
    raise AssertionError("unreachable")


def osv(queries: list[dict]) -> list[list[str]]:
    found: list[list[str]] = []
    for start in range(0, len(queries), 200):
        reply = fetch_json("https://api.osv.dev/v1/querybatch", {"queries": queries[start:start + 200]})
        found += [[v["id"] for v in result.get("vulns", [])] for result in reply["results"]]
    return found


def git(args: list[str], cwd: str, timeout: int = 900) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, timeout=timeout)


def blob_id(data: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def provenance(name: str, version: str, source: str, scratch: str, registry_commit: tuple[str, str] | None) -> list[str]:
    """Compare a package's published files with its repository. Returns problems."""
    info_path = os.path.join(source, ".cargo_vcs_info.json")
    if not os.path.exists(info_path):
        return ["package records no source commit"]
    info = json.load(open(info_path))
    commit, inner = info["git"]["sha1"], info.get("path_in_vcs", "")
    problems = ["packaged from a modified working tree"] if info["git"].get("dirty") else []
    manifest = open(os.path.join(source, "Cargo.toml")).read()
    match = re.search(r'^repository = "(https://[^/"]+/[^/"]+/[^/"#?]+?)(?:\.git)?/?(?:"|/)', manifest, re.M)
    if not match:
        return problems + ["no repository declared"]
    url = match[1]
    slug = url.split("://", 1)[1].removeprefix("github.com/")
    work = os.path.join(scratch, re.sub(r"[^A-Za-z0-9]+", "_", slug))
    if not os.path.isdir(work):
        os.makedirs(work)
        git(["init", "-q"], work)
    if git(["cat-file", "-e", commit + "^{commit}"], work).returncode != 0:
        if git(["fetch", "-q", "--depth", "1", url, commit], work).returncode != 0:
            time.sleep(6)
            if git(["fetch", "-q", "--depth", "1", url, commit], work).returncode != 0:
                return problems + [f"commit {commit[:10]} could not be fetched from {slug}"]
    tree = {}
    for line in git(["ls-tree", "-r", commit], work).stdout.decode().splitlines():
        meta, path = line.split("\t", 1)
        mode, _, oid = meta.split()
        tree[path] = (mode, oid)

    def lookup(path: str, depth: int = 0) -> str | None:
        """Blob id at `path`, following a symlink at any component."""
        parts = path.split("/")
        for end in range(1, len(parts) + 1):
            prefix = "/".join(parts[:end])
            entry = tree.get(prefix)
            if entry and entry[0] == "120000" and depth < 6:
                target = git(["cat-file", "blob", entry[1]], work).stdout.decode()
                resolved = os.path.normpath(os.path.join(os.path.dirname(prefix), target))
                return lookup("/".join([resolved, *parts[end:]]), depth + 1)
        entry = tree.get(path)
        return entry[1] if entry else None

    if "path_in_vcs" not in info and f"{name}/Cargo.toml" in tree:
        root_manifest = tree.get("Cargo.toml")
        root_text = git(["cat-file", "blob", root_manifest[1]], work).stdout.decode() if root_manifest else ""
        if not re.search(rf'^name = "{re.escape(name)}"', root_text, re.M):
            inner = name  # packaged before cargo recorded the folder

    for folder, _, files in os.walk(source):
        for file in files:
            relative = os.path.relpath(os.path.join(folder, file), source)
            if relative in SKIP:
                continue
            in_repo = "Cargo.toml" if relative == "Cargo.toml.orig" else relative
            content = blob_id(open(os.path.join(folder, file), "rb").read())
            expected = lookup(os.path.normpath(os.path.join(inner, in_repo)))
            if expected is None and relative.upper().startswith(("README", "LICENSE", "COPYING")):
                expected = lookup(relative)  # packaged from the workspace root
            if expected is None:
                problems.append(f"{relative} is not in the repository at {commit[:10]}")
            elif expected != content:
                problems.append(f"{relative} differs from the repository at {commit[:10]}")

    # Is the commit one the official repository vouches for?
    if registry_commit and registry_commit[0].lower() == slug.lower() and registry_commit[1] == commit:
        return problems  # recorded by the registry from the repository's own CI
    refs = subprocess.run(["git", "ls-remote", url], capture_output=True, text=True, timeout=300).stdout.splitlines()
    named = [ref.split("\t")[1] for ref in refs if ref.startswith(commit)]
    if any(ref.startswith("refs/tags/") or ref.startswith("refs/heads/") or ref == "HEAD" for ref in named):
        return problems
    full = work + "_history"
    if not os.path.isdir(full):
        subprocess.run(["git", "clone", "-q", "--filter=blob:none", "--no-checkout", url, full],
                       capture_output=True, timeout=1800)
    reachable = git(["for-each-ref", "--count=1", "--contains", commit, "refs/remotes", "refs/tags"], full)
    if reachable.returncode != 0 or not reachable.stdout.strip():
        problems.append(f"commit {commit[:10]} is not on any branch or tag of {slug}")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--base", default="origin/main", help="git ref to compare Cargo.lock against")
    parser.add_argument("--min-age-days", type=int, default=14)
    parser.add_argument("--all", action="store_true", help="give every registry package the closer look, not only added or changed ones")
    args = parser.parse_args()

    current = packages((ROOT / "Cargo.lock").read_text())
    base_text = subprocess.run(["git", "show", f"{args.base}:Cargo.lock"], cwd=ROOT, capture_output=True, text=True)
    if base_text.returncode != 0:
        print(f"Cannot read Cargo.lock at {args.base}", file=sys.stderr)
        return 1
    base = packages(base_text.stdout)
    registry = sorted(key for key, (source, _) in current.items() if source and source.startswith("registry+"))
    added = {key for key in registry if key not in base}
    changed = registry if args.all else sorted(added)
    exceptions = json.loads((ROOT / "scripts" / "dependency_age_exceptions.json").read_text())
    reviewed = json.loads((ROOT / "scripts" / "dependency_provenance_reviewed.json").read_text())
    attention = 0

    print(f"Lists: {len(registry)} registry packages at exact versions")
    for key, ids in zip(registry, osv([{"package": {"name": n, "ecosystem": "crates.io"}, "version": v} for n, v in registry])):
        if ids:
            new = key in added
            attention += new
            print(f"  {'ATTENTION' if new else 'on base  '} {key[0]}@{key[1]}: {', '.join(ids)}")
    names = sorted({name for name, _ in registry})
    for name, ids in zip(names, osv([{"package": {"name": n, "ecosystem": "crates.io"}} for n in names])):
        malicious = [i for i in ids if i.startswith("MAL-")]
        if malicious:
            attention += 1
            print(f"  ATTENTION {name}: malicious-package record {', '.join(malicious)}")
    print(f"  {len(names)} crate names checked for a malicious-package record")

    print((f"All registry packages: {len(changed)}" if args.all else f"Added or changed since {args.base}: {len(changed)} packages"))
    cache = glob.glob(os.path.expanduser("~/.cargo/registry/cache/*/"))
    sources = glob.glob(os.path.expanduser("~/.cargo/registry/src/*/"))
    now = datetime.datetime.now(datetime.timezone.utc)
    build_time = []
    with tempfile.TemporaryDirectory(prefix="dependency-provenance-") as scratch:
        for name, version in changed:
            label, problems = f"{name}@{version}", []
            checksum = current[(name, version)][1]
            meta = fetch_json(f"https://crates.io/api/v1/crates/{name}/{version}")["version"]
            time.sleep(0.4)
            if meta.get("yanked"):
                problems.append("yanked")
            if meta.get("checksum") != checksum:
                problems.append("registry checksum differs from Cargo.lock")
            age = (now - datetime.datetime.fromisoformat(meta["created_at"].replace("Z", "+00:00"))).days
            if age < args.min_age_days and label not in exceptions:
                problems.append(f"published {age} days ago (minimum {args.min_age_days}); add a reasoned exception or pin an older release")
            archive = next((p for c in cache if os.path.exists(p := f"{c}{name}-{version}.crate")), None)
            source = next((p for s in sources if os.path.isdir(p := f"{s}{name}-{version}")), None)
            if not archive or not source:
                problems.append("not in the cargo cache; run `cargo fetch --locked`, or the package is for another target")
            else:
                if hashlib.sha256(open(archive, "rb").read()).hexdigest() != checksum:
                    problems.append("cached archive differs from Cargo.lock")
                trusted = meta.get("trustpub_data") or {}
                recorded = (trusted["repository"], trusted["sha"]) if trusted.get("repository") and trusted.get("sha") else None
                differences = provenance(name, version, source, scratch, recorded)
                if differences and label in reviewed:
                    # A person looked at exactly this release. Cargo.lock pins
                    # its checksum, so the finding cannot go stale.
                    print(f"  reviewed  {label}: {reviewed[label]}")
                    print(f"            (was: {'; '.join(differences)[:300]})")
                    continue
                problems += differences
                manifest = open(os.path.join(source, "Cargo.toml")).read()
                if os.path.exists(os.path.join(source, "build.rs")) or re.search(r'^build = "', manifest, re.M):
                    build_time.append(label + " (build script)")
                if "proc-macro = true" in manifest:
                    build_time.append(label + " (proc-macro)")
            note = f"  [exception: {exceptions[label]}]" if label in exceptions and age < args.min_age_days else ""
            if problems:
                attention += 1
                print(f"  ATTENTION {label}: " + "; ".join(problems))
            else:
                print(f"  ok        {label}  {age} days old{note}")
    print("Runs code at build time among these: " + (", ".join(build_time) or "none"))
    print(f"{attention} item(s) need attention")
    return 1 if attention else 0


if __name__ == "__main__":
    raise SystemExit(main())
