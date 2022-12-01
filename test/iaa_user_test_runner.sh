#!/bin/bash -Ex
# SPDX-License-Identifier: GPL-2.0
# Copyright(c) 2019-2020 Intel Corporation. All rights reserved.

. "$(dirname "$0")/common"

rc="$EXIT_SKIP"

IAA=iax1
WQ0=wq1.4
WQ1=wq1.1

trap 'err $LINENO' ERR

[ ! -f "$IAATEST" ] && echo "fail: $LINENO" && exit 1

check_min_kver "5.6" || do_skip "kernel does not support idxd"

# skip if no pasid support as iaa_test does not support operation w/o pasid yet.
[ ! -f "/sys/bus/dsa/devices/$IAA/pasid_enabled" ] && echo "No SVM support" && exit "$EXIT_SKIP"

pasid_en=$(cat /sys/bus/dsa/devices/$IAA/pasid_enabled)
if [ "$pasid_en" -ne 1 ]; then
	exit "$EXIT_SKIP"
fi

start_iaa()
{
	configurable=$(cat /sys/bus/dsa/devices/$IAA/configurable)
	if [ "$configurable" ]; then
		"$ACCFG" load-config -c "$CONFIG2"
	fi
	"$ACCFG" enable-device "$IAA"
}

stop_iaa()
{
	"$ACCFG" disable-device "$IAA"
}

enable_wqs()
{
	"$ACCFG" enable-wq "$IAA"/"$WQ0"
	"$ACCFG" enable-wq "$IAA"/"$WQ1"
}

disable_wqs()
{
	"$ACCFG" disable-wq "$IAA"/"$WQ0"
	"$ACCFG" disable-wq "$IAA"/"$WQ1"
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
				"$IAATEST" -w "$wq_mode_code" -l "$xfer_size" -o "$opcode" \
					-f "$flag" -1 "$extra_flag" -t 5000 -v
			else
				"$IAATEST" -w "$wq_mode_code" -l "$xfer_size" -o "$opcode" \
					-f "$flag" -t 5000 -v
			fi
		done
	done
}

test_op_filter()
{
	local flag="$1"
	local wq_mode_code
	local wq_mode_name

	for wq_mode_code in 0 1; do
		wq_mode_name=$(wq_mode2name "$wq_mode_code")

		./iaa_test -w "$wq_mode_code" -f "$flag" -l 512 -2 0x7c -3 128 \
			-o 0x50 -t 5000 -v
		./iaa_test -w "$wq_mode_code" -f "$flag" -l 1024 -2 0x7c -3 256 \
			-o 0x50 -t 5000 -v
		./iaa_test -w "$wq_mode_code" -f "$flag" -l 4096 -2 0x7c -3 1024 \
			-o 0x50 -t 5000 -v
		./iaa_test -w "$wq_mode_code" -f "$flag" -l 65536 -2 0x7c -3 16384 \
			-o 0x50 -t 5000 -v
		./iaa_test -w "$wq_mode_code" -f "$flag" -l 1048576 -2 0x7c -3 262144 \
			-o 0x50 -t 5000 -v
		./iaa_test -w "$wq_mode_code" -f "$flag" -l 2097152 -2 0x7c -3 524288 \
			-o 0x50 -t 5000 -v

		./iaa_test -w "$wq_mode_code" -f "$flag" -l 512 -2 0x38 -3 256 \
			-o 0x51 -t 5000 -v
		./iaa_test -w "$wq_mode_code" -f "$flag" -l 1024 -2 0x38 -3 512 \
			-o 0x51 -t 5000 -v
		./iaa_test -w "$wq_mode_code" -f "$flag" -l 4096 -2 0x38 -3 2048 \
			-o 0x51 -t 5000 -v
		./iaa_test -w "$wq_mode_code" -f "$flag" -l 65536 -2 0x38 -3 32768 \
			-o 0x51 -t 5000 -v
		./iaa_test -w "$wq_mode_code" -f "$flag" -l 1048576 -2 0x38 -3 524288 \
			-o 0x51 -t 5000 -v
		./iaa_test -w "$wq_mode_code" -f "$flag" -l 2097152 -2 0x38 -3 1048576 \
			-o 0x51 -t 5000 -v

		./iaa_test -w "$wq_mode_code" -f "$flag" -l 512 -2 0x7c -3 128 \
			-o 0x52 -t 5000 -v
		./iaa_test -w "$wq_mode_code" -f "$flag" -l 1024 -2 0x7c -3 256 \
			-o 0x52 -t 5000 -v
		./iaa_test -w "$wq_mode_code" -f "$flag" -l 4096 -2 0x7c -3 1024 \
			-o 0x52 -t 5000 -v
		./iaa_test -w "$wq_mode_code" -f "$flag" -l 65536 -2 0x7c -3 16384 \
			-o 0x52 -t 5000 -v
		./iaa_test -w "$wq_mode_code" -f "$flag" -l 1048576 -2 0x7c -3 262144 \
			-o 0x52 -t 5000 -v
		./iaa_test -w "$wq_mode_code" -f "$flag" -l 2097152 -2 0x7c -3 524288 \
			-o 0x52 -t 5000 -v

		./iaa_test -w "$wq_mode_code" -f "$flag" -l 512 -2 0x7c -3 128 \
			-o 0x53 -t 5000 -v
		./iaa_test -w "$wq_mode_code" -f "$flag" -l 1024 -2 0x7c -3 256 \
			-o 0x53 -t 5000 -v
		./iaa_test -w "$wq_mode_code" -f "$flag" -l 4096 -2 0x7c -3 1024 \
			-o 0x53 -t 5000 -v
		./iaa_test -w "$wq_mode_code" -f "$flag" -l 65536 -2 0x7c -3 16384 \
			-o 0x53 -t 5000 -v
		./iaa_test -w "$wq_mode_code" -f "$flag" -l 1048576 -2 0x7c -3 262144 \
			-o 0x53 -t 5000 -v
		./iaa_test -w "$wq_mode_code" -f "$flag" -l 2097152 -2 0x7c -3 524288 \
			-o 0x53 -t 5000 -v

		./iaa_test -w "$wq_mode_code" -f "$flag" -l 512 -2 0x1c -3 512 \
			-o 0x54 -t 5000 -v
		./iaa_test -w "$wq_mode_code" -f "$flag" -l 1024 -2 0x1c -3 1024 \
			-o 0x54 -t 5000 -v
		./iaa_test -w "$wq_mode_code" -f "$flag" -l 4096 -2 0x1c -3 4096 \
			-o 0x54 -t 5000 -v
		./iaa_test -w "$wq_mode_code" -f "$flag" -l 32768 -2 0x1c -3 32768 \
			-o 0x54 -t 5000 -v
		./iaa_test -w "$wq_mode_code" -f "$flag" -l 65536 -2 0x1c -3 65536 \
			-o 0x54 -t 5000 -v
		./iaa_test -w "$wq_mode_code" -f "$flag" -l 131072 -2 0x1c -3 131072 \
			-o 0x54 -t 5000 -v

		./iaa_test -w "$wq_mode_code" -f "$flag" -l 32 -2 0x3c -3 16 \
			-o 0x54 -t 5000 -v
		./iaa_test -w "$wq_mode_code" -f "$flag" -l 64 -2 0x3c -3 32 \
			-o 0x54 -t 5000 -v
		./iaa_test -w "$wq_mode_code" -f "$flag" -l 128 -2 0x3c -3 64 \
			-o 0x54 -t 5000 -v
		./iaa_test -w "$wq_mode_code" -f "$flag" -l 256 -2 0x3c -3 128 \
			-o 0x54 -t 5000 -v
		./iaa_test -w "$wq_mode_code" -f "$flag" -l 512 -2 0x3c -3 256 \
			-o 0x54 -t 5000 -v
		./iaa_test -w "$wq_mode_code" -f "$flag" -l 1024 -2 0x3c -3 512 \
			-o 0x54 -t 5000 -v

		./iaa_test -w "$wq_mode_code" -f "$flag" -l 64 -2 0x7c -3 16 \
			-o 0x54 -t 5000 -v
		./iaa_test -w "$wq_mode_code" -f "$flag" -l 128 -2 0x7c -3 32 \
			-o 0x54 -t 5000 -v
		./iaa_test -w "$wq_mode_code" -f "$flag" -l 256 -2 0x7c -3 64 \
			-o 0x54 -t 5000 -v
		./iaa_test -w "$wq_mode_code" -f "$flag" -l 512 -2 0x7c -3 128 \
			-o 0x54 -t 5000 -v
		./iaa_test -w "$wq_mode_code" -f "$flag" -l 1024 -2 0x7c -3 256 \
			-o 0x54 -t 5000 -v
		./iaa_test -w "$wq_mode_code" -f "$flag" -l 2048 -2 0x7c -3 512 \
			-o 0x54 -t 5000 -v

		./iaa_test -w "$wq_mode_code" -f "$flag" -l 512 -2 0x38 -3 256 \
			-o 0x55 -t 5000 -v
		./iaa_test -w "$wq_mode_code" -f "$flag" -l 1024 -2 0x38 -3 512 \
			-o 0x55 -t 5000 -v
		./iaa_test -w "$wq_mode_code" -f "$flag" -l 4096 -2 0x38 -3 2048 \
			-o 0x55 -t 5000 -v
		./iaa_test -w "$wq_mode_code" -f "$flag" -l 65536 -2 0x38 -3 32768 \
			-o 0x55 -t 5000 -v
		./iaa_test -w "$wq_mode_code" -f "$flag" -l 1048576 -2 0x38 -3 524288 \
			-o 0x55 -t 5000 -v
		./iaa_test -w "$wq_mode_code" -f "$flag" -l 2097152 -2 0x38 -3 1048576 \
			-o 0x55 -t 5000 -v

		./iaa_test -w "$wq_mode_code" -f "$flag" -l 512 -2 0x7c -3 128 \
			-o 0x56 -t 5000 -v
		./iaa_test -w "$wq_mode_code" -f "$flag" -l 1024 -2 0x7c -3 256 \
			-o 0x56 -t 5000 -v
		./iaa_test -w "$wq_mode_code" -f "$flag" -l 4096 -2 0x7c -3 1024 \
			-o 0x56 -t 5000 -v
		./iaa_test -w "$wq_mode_code" -f "$flag" -l 65536 -2 0x7c -3 16384 \
			-o 0x56 -t 5000 -v
		./iaa_test -w "$wq_mode_code" -f "$flag" -l 1048576 -2 0x7c -3 262144 \
			-o 0x56 -t 5000 -v
		./iaa_test -w "$wq_mode_code" -f "$flag" -l 2097152 -2 0x7c -3 524288 \
			-o 0x56 -t 5000 -v
	done
}

_cleanup
start_iaa
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

flag="0x1"
extra_flag="0x8000"
echo "Testing with 'block on fault' flag ON"
for opcode in "0x44"; do
	test_op $opcode $flag $extra_flag
done

flag="0x0"
extra_flag="0x4000"
echo "Testing with 'block on fault' flag OFF"
for opcode in "0x44"; do
	test_op $opcode $flag $extra_flag
done

unset SIZE_1

flag="0x1"
echo "Testing with 'block on fault' flag ON"
for opcode in "0x4e" "0x4d" "0x49" "0x4c" "0x48" "0x43" "0x42"; do
	test_op $opcode $flag
done

flag="0x0"
echo "Testing with 'block on fault' flag OFF"
for opcode in "0x4e" "0x4d" "0x49" "0x4c" "0x48" "0x43" "0x42"; do
	test_op $opcode $flag
done

flag="0x1"
test_op_filter $flag

flag="0x0"
test_op_filter $flag

disable_wqs
stop_iaa
_cleanup
exit 0
