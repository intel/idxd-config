#!/bin/bash -Ex
# SPDX-License-Identifier: GPL-2.0
# Copyright(c) 2019-2020 Intel Corporation. All rights reserved.

. "$(dirname "$0")/common"

rc="$EXIT_SKIP"

IAX=iax1
WQ0=wq1.4
WQ1=wq1.1

trap 'err $LINENO' ERR

[ ! -f "$IAXTEST" ] && echo "fail: $LINENO" && exit 1

check_min_kver "5.6" || do_skip "kernel does not support idxd"

# skip if no pasid support as iaa_test does not support operation w/o pasid yet.
[ ! -f "/sys/bus/dsa/devices/$IAX/pasid_enabled" ] && echo "No SVM support" && exit "$EXIT_SKIP"

pasid_en=$(cat /sys/bus/dsa/devices/$IAX/pasid_enabled)
if [ "$pasid_en" -ne 1 ]; then
	exit "$EXIT_SKIP"
fi

start_iax()
{
	configurable=$(cat /sys/bus/dsa/devices/$IAX/configurable)
	if [ "$configurable" ]; then
		"$ACCFG" load-config -c "$CONFIG2"
	fi
	"$ACCFG" enable-device "$IAX"
}

stop_iax()
{
	"$ACCFG" disable-device "$IAX"
}

enable_wqs()
{
	"$ACCFG" enable-wq "$IAX"/"$WQ0"
	"$ACCFG" enable-wq "$IAX"/"$WQ1"
}

disable_wqs()
{
	"$ACCFG" disable-wq "$IAX"/"$WQ0"
	"$ACCFG" disable-wq "$IAX"/"$WQ1"
}

# Test operation with a given opcode
# $1: opcode (e.g. 0x3 for memmove)
# $2: flag (optional, default 0x3 for BOF on, 0x2 for BOF off)
#
test_op()
{
	local opcode="$1"
	local flag="$2"
	local extra_flag="$3"
	local op_name
	op_name=$(opcode2name "$opcode")
	local wq_mode_code
	local wq_mode_name

	for wq_mode_code in 0 1; do
		wq_mode_name=$(wq_mode2name "$wq_mode_code")
		echo "Performing $wq_mode_name WQ $op_name testing"
		for xfer_size in $SIZE_1 $SIZE_4K $SIZE_64K $SIZE_1M $SIZE_2M; do
			echo "Testing $xfer_size bytes"
			if [ "$extra_flag" != "" ]
			then
				"$IAXTEST" -w "$wq_mode_code" -l "$xfer_size" -o "$opcode" \
					-f "$flag" -e "$extra_flag" -t 5000 -v
			else
				"$IAXTEST" -w "$wq_mode_code" -l "$xfer_size" -o "$opcode" \
					-f "$flag" -t 5000 -v
			fi
		done
	done
}

_cleanup
start_iax
enable_wqs
# shellcheck disable=SC2034
rc="$EXIT_FAILURE"

flag="0x1"
echo "Testing with 'block on fault' flag ON"
for opcode in "0x0"; do
	test_op $opcode $flag
done

flag="0x0"
echo "Testing with 'block on fault' flag OFF"
for opcode in "0x0"; do
	test_op $opcode $flag
done

disable_wqs
stop_iax
_cleanup
exit 0
