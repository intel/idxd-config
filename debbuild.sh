#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# Copyright(c) 2021 Intel Corporation. All rights reserved.

set -e

[ -z "${DEBEMAIL}" ] || [ -z "${DEBFULLNAME}" ] && {
	echo
	echo "Please set following environment variables"
	echo
	echo 'DEBEMAIL="your.email.address@example.org"'
	echo 'DEBFULLNAME="Firstname Lastname"'
	echo
	exit
}

NAME=accel-config
REPODIR=idxd-config
REFDIR=$(pwd)
UPSTREAM=$REFDIR #TODO update once we have a public upstream
PKGDIR=debpkg

WORKDIR="$(mktemp -d --tmpdir "$NAME.XXXXXXXXXX")"
trap 'rm -rf $WORKDIR' exit

[ -d "$REFDIR" ] && REFERENCE="--reference $REFDIR"

echo
ch_entry=$(grep accel-config debian/changelog | head -n1)
echo Last entry in debian/changelog = \"$ch_entry\"

read -r -p 'Build package for this version? [y/N)] ' res
if [[ ! "$res" =~ [yY](es)* ]]
then
	echo
	echo "Please run ./debdch.sh or dch -r to update debian/changelog"
	echo
	exit
fi

dch -r ""

pushd $WORKDIR

git clone $REFERENCE "$UPSTREAM" $REPODIR

cp -r $REFDIR/deb* $REPODIR #temporary till initial commit

cd $REPODIR

debmake -t
DEB_BUILD_OPTIONS=nocheck debuild -us -uc

popd

rm -rf $PKGDIR
mkdir $PKGDIR
rm -rf $WORKDIR/*/
cp -r $WORKDIR/* $PKGDIR

echo
echo "!!!Debian package created in ./$PKGDIR and is ready for upload!!!"
echo "***debian/changelog was updated - please commit the changes***"
echo
