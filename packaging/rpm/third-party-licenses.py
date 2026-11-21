#!/usr/bin/env python3
"""Collect the license texts of the third-party crates built into the mikagami binary.

usage: third-party-licenses.py OUTDIR [--target TRIPLE] [--list-only]

Run in the source directory (the RPM %install runs it with the vendored sources). The crates
are the normal and build dependencies of the `mikagami` package for the target (cargo tree,
offline, locked); each crate's license files (LICENSE*, LICENCE*, COPYING*, UNLICENSE*,
NOTICE*) are copied to OUTDIR/<name>-<version>/ and OUTDIR/README.txt lists every crate with
its declared license. It fails (exit 1) when a crate cannot be found or has no license file,
so a package is never built with a missing notice. --list-only prints the list and copies
nothing.
"""
import json
import os
import re
import shutil
import subprocess
import sys

LICENSE_FILE = re.compile(r"^(licen[cs]e|copying|unlicense|notice)", re.IGNORECASE)


def cargo(*args):
    return subprocess.run(["cargo", *args], check=True, capture_output=True,
                          text=True).stdout


def main():
    args = sys.argv[1:]
    if not args:
        sys.exit(__doc__)
    out = args[0]
    target = None
    list_only = "--list-only" in args
    if "--target" in args:
        target = args[args.index("--target") + 1]
    tree = ["tree", "--offline", "--locked", "-e", "normal,build", "-p", "mikagami",
            "--prefix", "none", "--format", "{p}|{l}"]
    if target:
        tree += ["--target", target]
    crates = {}
    for line in cargo(*tree).splitlines():
        line = line.replace(" (*)", "").replace(" (proc-macro)", "").strip()
        if not line or "|" not in line:
            continue
        package, license_ = line.split("|", 1)
        name, _, version = package.partition(" v")
        version = version.split(" ", 1)[0]
        if name == "mikagami":
            continue
        crates[(name, version)] = license_
    metadata = json.loads(cargo("metadata", "--offline", "--locked", "--format-version", "1"))
    dirs = {(p["name"], p["version"]): os.path.dirname(p["manifest_path"])
            for p in metadata["packages"]}
    problems = []
    rows = []
    for (name, version), license_ in sorted(crates.items()):
        directory = dirs.get((name, version))
        if directory is None:
            problems.append(f"{name} {version}: not found in cargo metadata")
            continue
        files = sorted(f for f in os.listdir(directory)
                       if LICENSE_FILE.match(f) and os.path.isfile(os.path.join(directory, f)))
        if not files:
            problems.append(f"{name} {version}: no license file")
            continue
        rows.append((name, version, license_ or "(not declared)", files))
        if not list_only:
            dest = os.path.join(out, f"{name}-{version}")
            os.makedirs(dest, exist_ok=True)
            for f in files:
                shutil.copyfile(os.path.join(directory, f), os.path.join(dest, f))
    if problems:
        for p in problems:
            print(f"third-party-licenses: {p}", file=sys.stderr)
        sys.exit(1)
    listing = ["Third-party crates built into mikagami (name, version, declared license).",
               "Their license texts are in the directory of each crate next to this file.", ""]
    listing += [f"{n} {v}: {l}" for n, v, l, _ in rows]
    text = "\n".join(listing) + "\n"
    if list_only:
        sys.stdout.write(text)
        return
    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, "README.txt"), "w") as handle:
        handle.write(text)
    print(f"third-party-licenses: {len(rows)} crates")


if __name__ == "__main__":
    main()
