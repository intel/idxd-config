#!/bin/bash -Ex
# SPDX-License-Identifier: GPL-2.0
# Copyright(c) 2019-2020 Intel Corporation. All rights reserved.

. "$(dirname "$0")/common"

rc="$EXIT_SKIP"

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
		"$ACCFG" load-config -c "$CONFIG1"
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

# Test operation with a given opcode
# $1: opcode (e.g. 0x3 for memmove)
# $2: flag (optional, default 0x3 for BOF on, 0x2 for BOF off)
#
test_op()
{
	local opcode="$1"
	local flag="$2"
	local op_name
	op_name=$(opcode2name "$opcode")
	local wq_mode_code
	local wq_mode_name
	local xfer_size

	for wq_mode_code in 0 1; do
		wq_mode_name=$(wq_mode2name "$wq_mode_code")
		echo "Performing $wq_mode_name WQ $op_name testing"
		for xfer_size in $SIZE_4K $SIZE_64K $SIZE_1M $SIZE_2M; do
			echo "Testing $xfer_size bytes"
			"$DSATEST" -w "$wq_mode_code" -l "$xfer_size" -o "$opcode" \
				-f "$flag" t200 -v
		done
	done
}

# Test operation in batch mode with a given opcode
# $1: opcode (e.g. 0x3 for memmove)
# $2: flag (optional, default 0x3 for BOF on, 0x2 for BOF off)
#
test_op_batch()
{
	local opcode="$1"
	local flag="$2"
	local op_name
	op_name=$(opcode2name "$opcode")
	local wq_mode_code
	local wq_mode_name
	local xfer_size

	for wq_mode_code in 0 1; do
		wq_mode_name=$(wq_mode2name "$wq_mode_code")
		echo "Performing $wq_mode_name WQ batched $op_name testing"
		for xfer_size in $SIZE_4K $SIZE_64K $SIZE_1M $SIZE_2M; do
			echo "Testing $xfer_size bytes"
			"$DSATEST" -w "$wq_mode_code" -l "$xfer_size" -o 0x1 -b "$opcode" \
				-c 16 -f "$flag" t2000 -v
		done
	done
}

_cleanup
start_dsa
enable_wqs
# shellcheck disable=SC2034
rc="$EXIT_FAILURE"

flag="0x1"
echo "Testing with 'block on fault' flag ON"
for opcode in "0x3" "0x4" "0x5" "0x6" "0x9"; do
	test_op $opcode $flag
	test_op_batch $opcode $flag
done

flag="0x0"
echo "Testing with 'block on fault' flag OFF"
for opcode in "0x3" "0x4" "0x5" "0x6" "0x9"; do
	test_op $opcode $flag
	test_op_batch $opcode $flag
done

disable_wqs
stop_dsa
_cleanup
exit 0
