#!/bin/sh
# Build the Mikagami RPM (packaging/rpm/mikagami.spec).
#
# usage:
#   build.sh sources --out DIR [--rev REV]
#       Writes DIR/mikagami-VERSION.tar.gz (git archive of REV, default HEAD,
#       limited to the files the build needs) and DIR/mikagami-VERSION-vendor.tar.gz
#       (`cargo vendor --locked` of the crate dependencies, for an offline
#       build). Runs on any host with git and cargo (macOS included).
#   build.sh rpm --out DIR [--release N] [--system-rust]
#       Runs rpmbuild -ba with the sources of DIR, topdir DIR/rpmbuild.
#       Linux only (rpmbuild, systemd-rpm-macros, gcc, and the pinned Rust
#       toolchain in PATH unless --system-rust).
#
# Neither step installs anything on the build host, starts any unit or needs
# root.
set -eu

VERSION=0.8.0
NAME=mikagami
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)

die() { echo "build.sh: $*" >&2; exit 1; }

[ $# -ge 1 ] || die "usage: build.sh sources|rpm --out DIR [...]"
step=$1; shift
out=""; rev=HEAD; release=1; system_rust=0
while [ $# -gt 0 ]; do
  case "$1" in
    --out) [ $# -ge 2 ] || die "--out needs a value"; out=$2; shift 2 ;;
    --rev) [ $# -ge 2 ] || die "--rev needs a value"; rev=$2; shift 2 ;;
    --release)
      [ $# -ge 2 ] || die "--release needs a value"
      case "$2" in ""|*[!0-9]*) die "--release must be a positive integer" ;; esac
      release=$2; shift 2 ;;
    --system-rust) system_rust=1; shift ;;
    *) die "unknown argument: $1" ;;
  esac
done
[ -n "$out" ] || die "--out DIR is required"
mkdir -p "$out"
out=$(cd "$out" && pwd)

case "$step" in
  sources)
    command -v git >/dev/null || die "git is required"
    command -v cargo >/dev/null || die "cargo is required"
    # Only the files the build, the %check and the docs need.
    git -C "$repo" archive --format=tar --prefix="$NAME-$VERSION/" "$rev" -- \
      Cargo.toml Cargo.lock rust-toolchain.toml README.md LICENSE THIRD_PARTY_LICENSES.md \
      TWO_NODE_ARCHITECTURE.md \
      TWO_NODE_SAFETY_MODEL.md TWO_NODE_FAILURE_MATRIX.md src contrib docs packaging \
      | gzip -n -9 > "$out/$NAME-$VERSION.tar.gz"
    work="$out/vendor-work"
    rm -rf "$work"
    mkdir -p "$work"
    tar -xzf "$out/$NAME-$VERSION.tar.gz" -C "$work"
    (cd "$work/$NAME-$VERSION" && cargo vendor -q --locked --versioned-dirs vendor >/dev/null)
    # Deterministic member order; owner root:root so that no build-host user
    # name enters the tarball; no extended attributes / AppleDouble members
    # (macOS). The timestamps are cargo's.
    if tar --version 2>/dev/null | grep -q 'GNU tar'; then
      set -- --owner=0 --group=0 --numeric-owner
    else
      set -- --uid 0 --gid 0 --uname root --gname root --no-xattrs --no-mac-metadata
    fi
    (cd "$work/$NAME-$VERSION" && find vendor -print | LC_ALL=C sort > ../vendor.list \
      && COPYFILE_DISABLE=1 tar "$@" --no-recursion -cf - -T ../vendor.list) \
      | gzip -n -9 > "$out/$NAME-$VERSION-vendor.tar.gz"
    rm -rf "$work"
    (cd "$out" && if command -v sha256sum >/dev/null; then
        sha256sum "$NAME-$VERSION.tar.gz" "$NAME-$VERSION-vendor.tar.gz"
      else
        shasum -a 256 "$NAME-$VERSION.tar.gz" "$NAME-$VERSION-vendor.tar.gz"
      fi > SOURCES.sha256)
    cat "$out/SOURCES.sha256"
    ;;
  rpm)
    [ "$(uname -s)" = Linux ] || die "rpmbuild runs on Linux only"
    command -v rpmbuild >/dev/null || die "rpmbuild is required (dnf install rpm-build)"
    for f in "$NAME-$VERSION.tar.gz" "$NAME-$VERSION-vendor.tar.gz"; do
      [ -f "$out/$f" ] || die "$out/$f is missing; run: build.sh sources --out $out"
    done
    top="$out/rpmbuild"
    mkdir -p "$top/SOURCES" "$top/SPECS" "$top/BUILD" "$top/RPMS" "$top/SRPMS"
    cp "$out/$NAME-$VERSION.tar.gz" "$out/$NAME-$VERSION-vendor.tar.gz" "$top/SOURCES/"
    # The spec is the one of the source tarball, so the RPM matches its sources.
    tar -xzf "$out/$NAME-$VERSION.tar.gz" -C "$top/SPECS" --strip-components=3 \
      "$NAME-$VERSION/packaging/rpm/$NAME.spec"
    set -- --define "_topdir $top" --define "mkg_release $release"
    [ "$system_rust" -eq 0 ] || set -- "$@" --with system_rust
    rpmbuild -ba "$@" "$top/SPECS/$NAME.spec"
    find "$top/RPMS" "$top/SRPMS" -name '*.rpm' -print
    ;;
  *) die "unknown step: $step (sources|rpm)" ;;
esac
