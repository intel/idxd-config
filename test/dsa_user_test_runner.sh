#!/bin/bash -E
# SPDX-License-Identifier: GPL-2.0
# Copyright(c) 2019-2020 Intel Corporation. All rights reserved.

. "$(dirname "$0")/common"

rc="$EXIT_SKIP"

if [[ $* =~ "--verbose" ]]; then
    VERBOSE="-v"
    set -x
else
    VERBOSE=""
fi

if [[ $* =~ "--skip-config" ]]; then
    SKIPCONFIG="true"
    DEV=`ls /dev/dsa/ | sed -ne 's|wq\([^.]\+\)\(.*\)|dsa\1/wq\1\2|p'`
    DSA=`echo $DEV | cut -f1 -d/`
    echo "$DEV"
    echo "$DSA"
else
    DSA=dsa0
    echo "$DSA"
fi
WQ0=wq0.0
WQ1=wq0.1

trap 'err $LINENO' ERR

[ ! -f "$DSATEST" ] && echo "fail: $LINENO" && exit 1

check_min_kver "5.6" || do_skip "kernel does not support idxd"

# skip if no pasid support as dsa_test does not support operation w/o pasid yet.
[ ! -f "/sys/bus/dsa/devices/$DSA/pasid_enabled" ] && echo "No SVM support" && exit "$EXIT_SKIP"

pasid_en=$(cat /sys/bus/dsa/devices/$DSA/pasid_enabled)
if [ "$pasid_en" -ne 1 ]; then
	exit "$EXIT_SKIP"
fi

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
		for xfer_size in $SIZE_1 $SIZE_4K $SIZE_64K $SIZE_1M $SIZE_2M; do
			echo "Testing $xfer_size bytes"
			if ! test -z "${SKIPCONFIG}"; then
			"$DSATEST" -l "$xfer_size" -o "$opcode" \
				-f "$flag" t200 "${VERBOSE}" -d "$DEV"
			else
			"$DSATEST" -w "$wq_mode_code" -l "$xfer_size" -o "$opcode" \
				-f "$flag" t200 "${VERBOSE}"
			fi
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

    if [ $opcode == "0x2" ];then
        return 0
    fi

	for wq_mode_code in 0 1; do
		wq_mode_name=$(wq_mode2name "$wq_mode_code")
		echo "Performing $wq_mode_name WQ batched $op_name testing"
		for xfer_size in $SIZE_1 $SIZE_4K $SIZE_64K $SIZE_1M $SIZE_2M; do
			echo "Testing $xfer_size bytes"
			if ! test -z "${SKIPCONFIG}"; then
			"$DSATEST" -l "$xfer_size" -o 0x1 -b "$opcode" \
				-c 16 -f "$flag" t2000 "${VERBOSE}" -d "$DEV"
			else
			"$DSATEST" -w "$wq_mode_code" -l "$xfer_size" -o 0x1 -b "$opcode" \
				-c 16 -f "$flag" t2000 "${VERBOSE}"
			fi
		done
	done
}

# Test operation with a given opcode
# $1: opcode (e.g. 0x3 for memmove)
# $2: flag (optional, default 0x3 for BOF on, 0x2 for BOF off)
#
test_dif_op()
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
		for xfer_size in $SIZE_512 $SIZE_1K $SIZE_4K; do
			echo "Testing $xfer_size bytes"
			if ! test -z "${SKIPCONFIG}"; then
			"$DSATEST" -l "$xfer_size" -o "$opcode" \
				-f "$flag" t200 "${VERBOSE}" -d "$DEV"
			else
			"$DSATEST" -w "$wq_mode_code" -l "$xfer_size" -o "$opcode" \
				-f "$flag" t200 "${VERBOSE}"
			fi
		done
	done
}

# Test operation in batch mode with a given opcode
# $1: opcode (e.g. 0x3 for memmove)
# $2: flag (optional, default 0x3 for BOF on, 0x2 for BOF off)
#
test_dif_op_batch()
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
		for xfer_size in $SIZE_512 $SIZE_1K $SIZE_4K; do
			echo "Testing $xfer_size bytes"
			if ! test -z "${SKIPCONFIG}"; then
			"$DSATEST" -l "$xfer_size" -o 0x1 -b "$opcode" \
				-c 16 -f "$flag" t2000 "${VERBOSE}" -d "$DEV"
			else
			"$DSATEST" -w "$wq_mode_code" -l "$xfer_size" -o 0x1 -b "$opcode" \
				-c 16 -f "$flag" t2000 "${VERBOSE}"
			fi
		done
	done
}
if test -z "${SKIPCONFIG}"; then
_cleanup
start_dsa
enable_wqs
fi
# shellcheck disable=SC2034
rc="$EXIT_FAILURE"

flag="0x1"
echo "Testing with 'block on fault' flag ON"
for opcode in "0x0" "0x2" "0x3" "0x4" "0x5" "0x6" "0x9" "0x10" "0x11" "0x20"; do
	test_op $opcode $flag
	test_op_batch $opcode $flag
done

flag="0x0"
echo "Testing with 'block on fault' flag OFF"
for opcode in "0x0" "0x2" "0x3" "0x4" "0x5" "0x6" "0x9" "0x10" "0x11" "0x20"; do
	test_op $opcode $flag
	test_op_batch $opcode $flag
done

# For DIF
flag="0x1"
echo "Testing with 'block on fault' flag ON"
for opcode in "0x12" "0x13" "0x14" "0x15"; do
	test_dif_op $opcode $flag
	test_dif_op_batch $opcode $flag
done

flag="0x0"
echo "Testing with 'block on fault' flag OFF"
for opcode in "0x12" "0x13" "0x14" "0x15"; do
	test_dif_op $opcode $flag
	test_dif_op_batch $opcode $flag
done

if ! $SKIPCONFIG; then
disable_wqs
stop_dsa
_cleanup
exit 0
fi
