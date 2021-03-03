#!/bin/bash
set -e

NAME=accel-config
REFDIR=$(pwd)
UPSTREAM=$REFDIR #TODO update once we have a public upstream
OUTDIR=$HOME/rpmbuild/SOURCES

[ -n "$1" ] && HEAD="$1" || HEAD="HEAD"

WORKDIR="$(mktemp -d --tmpdir "$NAME.XXXXXXXXXX")"
trap 'rm -rf $WORKDIR' exit

[ -d "$REFDIR" ] && REFERENCE="--reference $REFDIR"
git clone $REFERENCE "$UPSTREAM" "$WORKDIR"

VERSION=$(./git-version)
DIRNAME="accel-config-${VERSION}"
git archive --remote="$WORKDIR" --format=tar --prefix="$DIRNAME/" HEAD | gzip > $OUTDIR/"accel-config-${VERSION}.tar.gz"

echo "Written $OUTDIR/accel-config-${VERSION}.tar.gz"
