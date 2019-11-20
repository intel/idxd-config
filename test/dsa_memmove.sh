#!/bin/bash -Ex
# SPDX-License-Identifier: GPL-2.0
# Copyright(c) 2019 Intel Corporation. All rights reserved.

rc=77

. ./common

DSATEST=./dsa_test
CONFIG=./configs/2g2q_user_1.conf
DSA=dsa0
WQ0=wq0.0
WQ1=wq0.1

trap 'err $LINENO' ERR

[ ! -f "$DSATEST" ] && echo "fail: $LINENO" && exit 1

check_min_kver "5.6" || do_skip "kernel does not support idxd"

start_dsa()
{
	configurable=$(cat /sys/bus/dsa/devices/$DSA/configurable)
	if [ "$configurable" ]; then
		"$ACCFG" load-config -c "$CONFIG"
	fi
	"$ACCFG" enable-device "$DSA"
}

stop_dsa()
{
	"$ACCFG" disable-device "$DSA"
}

enable_wqs()
{
	"$ACCFG" enable-wq "$DSA"/"$WQ0"
	"$ACCFG" enable-wq "$DSA"/"$WQ1"
}

disable_wqs()
{
	"$ACCFG" disable-wq "$DSA"/"$WQ0"
	"$ACCFG" disable-wq "$DSA"/"$WQ1"
}

test_memmove()
{
	echo "Performing shared WQ MEMMOVE testing"
	echo "Testing $SIZE_4K bytes"
	"$DSATEST" -w 1 -l "$SIZE_4K" -o0x3 -t200
	echo "Testing $SIZE_64K bytes"
	"$DSATEST" -w 1 -l "$SIZE_64K" -o0x3 -t200
	echo "Testing $SIZE_1M bytes"
	"$DSATEST" -w 1 -l "$SIZE_1M" -o0x3 -t200
	echo "Testing $SIZE_2M bytes"
	"$DSATEST" -w 1 -l "$SIZE_2M" -o0x3 -t200

	echo "Performing dedicated WQ MEMMOVE testing"
	echo "Testing $SIZE_4K bytes"
	"$DSATEST" -w 0 -l "$SIZE_4K" -o0x3 -t200
	echo "Testing $SIZE_64K bytes"
	"$DSATEST" -w 0 -l "$SIZE_64K" -o0x3 -t200
	echo "Testing $SIZE_1M bytes"
	"$DSATEST" -w 0 -l "$SIZE_1M" -o0x3 -t200
	echo "Testing $SIZE_2M bytes"
	"$DSATEST" -w 0 -l "$SIZE_2M" -o0x3 -t200
}

test_memmove_batch()
{
	echo "Performing shared WQ batched MEMMOVE testing"
	echo "Testing $SIZE_4K bytes"
	"$DSATEST" -w 1 -l "$SIZE_4K" -o0x1 -b0x3 -c16 -t2000

	echo "Performing dedicated WQ batched MEMMOVE testing"
	echo "Testing $SIZE_4K bytes"
	"$DSATEST" -w 0 -l "$SIZE_4K" -o0x1 -b0x3 -c16 -t2000
}

_cleanup
start_dsa
enable_wqs
rc=1

test_memmove
test_memmove_batch

disable_wqs
stop_dsa
_cleanup
exit 0
