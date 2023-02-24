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

[ -n "$1" ] && REVISION=$1 || REVISION=1

VERSION=$(echo $(./git-version) | sed 's/\.git.*//')
DEB_VERSION=$VERSION-$REVISION

echo
echo "Updating debian/changelog.."
echo "accel-config version = $VERSION"
echo "Debian revision = $REVISION"
echo "New version = $DEB_VERSION"
echo
echo "Adding changes..."
echo

dch -v $DEB_VERSION --package accel-config -D unstable ""
cur_release=HEAD
prev_release=$(git describe --tags --abbrev=0 $cur_release^)
git shortlog $prev_release..$cur_release --invert-grep \
		--grep=release 2>/dev/null |
	while IFS= read -r line || [ -n "$line" ];
	do
		if [[ "$line" == *"):" ]]; then
			line=$(echo $line | sed -e "s/ ([0-9]*):$//")
			line="[ "$line" ]"
		else
			line=$(echo $line | sed -e "s/^.*: //")
		fi
		dch -a "$line" 2>/dev/null
		echo "* $line"
	done

echo
echo Please run "dch -r" to review and update debian/changelog before building package
echo
