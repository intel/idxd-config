#!/bin/bash -E
# SPDX-License-Identifier: GPL-2.0
# Copyright(c) 2019-2020 Intel Corporation. All rights reserved.

. "$(dirname "$0")/common"

rc="$EXIT_SKIP"

DEV_OPT=""

if [[ $* =~ "--verbose" ]]; then
	VERBOSE="-v"
	set -x
else
	VERBOSE=""
fi

if [[ $* =~ "--skip-config" ]]; then
	DEV=`ls /dev/iax/ | sed -ne 's|wq\([^.]\+\)\(.*\)|iax\1/wq\1\2|p'`
	DEV=`echo $DEV | cut -f1 -d' '`
	IAA=`echo $DEV | cut -f1 -d/`
	DEV_OPT="-d $DEV"
	echo "$DEV"
        SKIPCONFIG="true"
else
	IAA=iax1
fi
echo "$IAA"
WQ0=wq1.4
WQ1=wq1.1

IAA_OPCODE_NOOP=0x0
IAA_OPCODE_TRANSL_FETCH=0xa
IAA_OPCODE_DECRYPT=0x40
IAA_OPCODE_ENCRYPT=0x41
IAA_OPCODE_DECOMPRESS=0x42
IAA_OPCODE_COMPRESS=0x43
IAA_OPCODE_CRC64=0x44
IAA_OPCODE_ZDECOMPRESS32=0x48
IAA_OPCODE_ZDECOMPRESS16=0x49
IAA_OPCODE_ZDECOMPRESS8=0x4a
IAA_OPCODE_ZCOMPRESS32=0x4c
IAA_OPCODE_ZCOMPRESS16=0x4d
IAA_OPCODE_ZCOMPRESS8=0x4e
IAA_OPCODE_SCAN=0x50
IAA_OPCODE_SET_MEMBERSHIP=0x51
IAA_OPCODE_EXTRACT=0x52
IAA_OPCODE_SELECT=0x53
IAA_OPCODE_RLE_BURST=0x54
IAA_OPCODE_FIND_UNIQUE=0x55
IAA_OPCODE_EXPAND=0x56

IAA_OPCODE_MASK_NOOP=$((1 << IAA_OPCODE_NOOP))
IAA_OPCODE_MASK_TRANSL_FETCH=$((1 << IAA_OPCODE_TRANSL_FETCH))
IAA_OPCODE_MASK_DECRYPT=$((1 << IAA_OPCODE_DECRYPT))
IAA_OPCODE_MASK_ENCRYPT=$((1 << IAA_OPCODE_ENCRYPT))
IAA_OPCODE_MASK_DECOMPRESS=$((1 << IAA_OPCODE_DECOMPRESS))
IAA_OPCODE_MASK_COMPRESS=$((1 << IAA_OPCODE_COMPRESS))
IAA_OPCODE_MASK_CRC64=$((1 << IAA_OPCODE_CRC64))
IAA_OPCODE_MASK_ZDECOMPRESS32=$((1 << IAA_OPCODE_ZDECOMPRESS32))
IAA_OPCODE_MASK_ZDECOMPRESS16=$((1 << IAA_OPCODE_ZDECOMPRESS16))
IAA_OPCODE_MASK_ZDECOMPRESS8=$((1 << IAA_OPCODE_ZDECOMPRESS8))
IAA_OPCODE_MASK_ZCOMPRESS32=$((1 << IAA_OPCODE_ZCOMPRESS32))
IAA_OPCODE_MASK_ZCOMPRESS16=$((1 << IAA_OPCODE_ZCOMPRESS16))
IAA_OPCODE_MASK_ZCOMPRESS8=$((1 << IAA_OPCODE_ZCOMPRESS8))
IAA_OPCODE_MASK_SCAN=$((1 << IAA_OPCODE_SCAN))
IAA_OPCODE_MASK_SET_MEMBERSHIP=$((1 << IAA_OPCODE_SET_MEMBERSHIP))
IAA_OPCODE_MASK_EXTRACT=$((1 << IAA_OPCODE_EXTRACT))
IAA_OPCODE_MASK_SELECT=$((1 << IAA_OPCODE_SELECT))
IAA_OPCODE_MASK_RLE_BURST=$((1 << IAA_OPCODE_RLE_BURST))
IAA_OPCODE_MASK_FIND_UNIQUE=$((1 << IAA_OPCODE_FIND_UNIQUE))
IAA_OPCODE_MASK_EXPAND=$((1 << IAA_OPCODE_EXPAND))

OP_CAP0=`cat /sys/bus/dsa/devices/iax1/op_cap | awk -F ',' '{print $NF}'`
OP_CAP0="0x$OP_CAP0"
OP_CAP2=`cat /sys/bus/dsa/devices/iax1/op_cap | awk -F ',' '{print $(NF - 2)}'`
OP_CAP2="0x$OP_CAP2"

trap err_exit ERR

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

err_exit()
{
	err_code=$?
	if [ "$VFIO_BINDED" == "1" ]
	then
		unbind_vfio
	fi
	exit "$err_code"
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
					-f "$flag" -1 "$extra_flag" -t 5000 "${VERBOSE}" $DEV_OPT
			else
				"$IAATEST" -w "$wq_mode_code" -l "$xfer_size" -o "$opcode" \
					-f "$flag" -t 5000 "${VERBOSE}" $DEV_OPT
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

		if [ $((IAA_OPCODE_MASK_SCAN & OP_CAP2)) -ne 0 ]; then
			"$IAATEST" -w "$wq_mode_code" -f "$flag" -l 512 -2 0x7c \
				-3 128 -o $IAA_OPCODE_SCAN -t 5000 "${VERBOSE}" $DEV_OPT
			"$IAATEST" -w "$wq_mode_code" -f "$flag" -l 1024 -2 0x7c \
				-3 256 -o $IAA_OPCODE_SCAN -t 5000 "${VERBOSE}" $DEV_OPT
			"$IAATEST" -w "$wq_mode_code" -f "$flag" -l 4096 -2 0x7c \
				-3 1024 -o $IAA_OPCODE_SCAN -t 5000 "${VERBOSE}" $DEV_OPT
			"$IAATEST" -w "$wq_mode_code" -f "$flag" -l 65536 -2 0x7c \
				-3 16384 -o $IAA_OPCODE_SCAN -t 5000 "${VERBOSE}" $DEV_OPT
			"$IAATEST" -w "$wq_mode_code" -f "$flag" -l 1048576 -2 0x7c \
				-3 262144 -o $IAA_OPCODE_SCAN -t 5000 "${VERBOSE}" $DEV_OPT
			"$IAATEST" -w "$wq_mode_code" -f "$flag" -l 2097152 -2 0x7c \
				-3 524288 -o $IAA_OPCODE_SCAN -t 5000 "${VERBOSE}" $DEV_OPT
		fi

		if [ $((IAA_OPCODE_MASK_SET_MEMBERSHIP & OP_CAP2)) -ne 0 ]; then
			"$IAATEST" -w "$wq_mode_code" -f "$flag" -l 512 -2 0x38 \
				-3 256 -o $IAA_OPCODE_SET_MEMBERSHIP -t 5000 "${VERBOSE}" $DEV_OPT
			"$IAATEST" -w "$wq_mode_code" -f "$flag" -l 1024 -2 0x38 \
				-3 512 -o $IAA_OPCODE_SET_MEMBERSHIP -t 5000 "${VERBOSE}" $DEV_OPT
			"$IAATEST" -w "$wq_mode_code" -f "$flag" -l 4096 -2 0x38 \
				-3 2048 -o $IAA_OPCODE_SET_MEMBERSHIP -t 5000 "${VERBOSE}" $DEV_OPT
			"$IAATEST" -w "$wq_mode_code" -f "$flag" -l 65536 -2 0x38 \
				-3 32768 -o $IAA_OPCODE_SET_MEMBERSHIP -t 5000 "${VERBOSE}" $DEV_OPT
			"$IAATEST" -w "$wq_mode_code" -f "$flag" -l 1048576 -2 0x38 \
				-3 524288 -o $IAA_OPCODE_SET_MEMBERSHIP -t 5000 "${VERBOSE}" $DEV_OPT
			"$IAATEST" -w "$wq_mode_code" -f "$flag" -l 2097152 -2 0x38 \
				-3 1048576 -o $IAA_OPCODE_SET_MEMBERSHIP -t 5000 "${VERBOSE}" $DEV_OPT
		fi

		if [ $((IAA_OPCODE_MASK_EXTRACT & OP_CAP2)) -ne 0 ]; then
			"$IAATEST" -w "$wq_mode_code" -f "$flag" -l 512 -2 0x7c \
				-3 128 -o $IAA_OPCODE_EXTRACT -t 5000 "${VERBOSE}" $DEV_OPT
			"$IAATEST" -w "$wq_mode_code" -f "$flag" -l 1024 -2 0x7c \
				-3 256 -o $IAA_OPCODE_EXTRACT -t 5000 "${VERBOSE}" $DEV_OPT
			"$IAATEST" -w "$wq_mode_code" -f "$flag" -l 4096 -2 0x7c \
				-3 1024 -o $IAA_OPCODE_EXTRACT -t 5000 "${VERBOSE}" $DEV_OPT
			"$IAATEST" -w "$wq_mode_code" -f "$flag" -l 65536 -2 0x7c \
				-3 16384 -o $IAA_OPCODE_EXTRACT -t 5000 "${VERBOSE}" $DEV_OPT
			"$IAATEST" -w "$wq_mode_code" -f "$flag" -l 1048576 -2 0x7c \
				-3 262144 -o $IAA_OPCODE_EXTRACT -t 5000 "${VERBOSE}" $DEV_OPT
			"$IAATEST" -w "$wq_mode_code" -f "$flag" -l 2097152 -2 0x7c \
				-3 524288 -o $IAA_OPCODE_EXTRACT -t 5000 "${VERBOSE}" $DEV_OPT
		fi

		if [ $((IAA_OPCODE_MASK_SELECT & OP_CAP2)) -ne 0 ]; then
			"$IAATEST" -w "$wq_mode_code" -f "$flag" -l 512 -2 0x7c \
				-3 128 -o $IAA_OPCODE_SELECT -t 5000 "${VERBOSE}" $DEV_OPT
			"$IAATEST" -w "$wq_mode_code" -f "$flag" -l 1024 -2 0x7c \
				-3 256 -o $IAA_OPCODE_SELECT -t 5000 "${VERBOSE}" $DEV_OPT
			"$IAATEST" -w "$wq_mode_code" -f "$flag" -l 4096 -2 0x7c \
				-3 1024 -o $IAA_OPCODE_SELECT -t 5000 "${VERBOSE}" $DEV_OPT
			"$IAATEST" -w "$wq_mode_code" -f "$flag" -l 65536 -2 0x7c \
				-3 16384 -o $IAA_OPCODE_SELECT -t 5000 "${VERBOSE}" $DEV_OPT
			"$IAATEST" -w "$wq_mode_code" -f "$flag" -l 1048576 -2 0x7c \
				-3 262144 -o $IAA_OPCODE_SELECT -t 5000 "${VERBOSE}" $DEV_OPT
			"$IAATEST" -w "$wq_mode_code" -f "$flag" -l 2097152 -2 0x7c \
				-3 524288 -o $IAA_OPCODE_SELECT -t 5000 "${VERBOSE}" $DEV_OPT
		fi

		if [ $((IAA_OPCODE_MASK_RLE_BURST & OP_CAP2)) -ne 0 ]; then
			"$IAATEST" -w "$wq_mode_code" -f "$flag" -l 512 -2 0x1c \
				-3 512 -o $IAA_OPCODE_RLE_BURST -t 5000 "${VERBOSE}" $DEV_OPT
			"$IAATEST" -w "$wq_mode_code" -f "$flag" -l 1024 -2 0x1c \
				-3 1024 -o $IAA_OPCODE_RLE_BURST -t 5000 "${VERBOSE}" $DEV_OPT
			"$IAATEST" -w "$wq_mode_code" -f "$flag" -l 4096 -2 0x1c \
				-3 4096 -o $IAA_OPCODE_RLE_BURST -t 5000 "${VERBOSE}" $DEV_OPT
			"$IAATEST" -w "$wq_mode_code" -f "$flag" -l 32768 -2 0x1c \
				-3 32768 -o $IAA_OPCODE_RLE_BURST -t 5000 "${VERBOSE}" $DEV_OPT
			"$IAATEST" -w "$wq_mode_code" -f "$flag" -l 65536 -2 0x1c \
				-3 65536 -o $IAA_OPCODE_RLE_BURST -t 5000 "${VERBOSE}" $DEV_OPT
			"$IAATEST" -w "$wq_mode_code" -f "$flag" -l 131072 -2 0x1c \
				-3 131072 -o $IAA_OPCODE_RLE_BURST -t 5000 "${VERBOSE}" $DEV_OPT

			"$IAATEST" -w "$wq_mode_code" -f "$flag" -l 32 -2 0x3c \
				-3 16 -o $IAA_OPCODE_RLE_BURST -t 5000 "${VERBOSE}" $DEV_OPT
			"$IAATEST" -w "$wq_mode_code" -f "$flag" -l 64 -2 0x3c \
				-3 32 -o $IAA_OPCODE_RLE_BURST -t 5000 "${VERBOSE}" $DEV_OPT
			"$IAATEST" -w "$wq_mode_code" -f "$flag" -l 128 -2 0x3c \
				-3 64 -o $IAA_OPCODE_RLE_BURST -t 5000 "${VERBOSE}" $DEV_OPT
			"$IAATEST" -w "$wq_mode_code" -f "$flag" -l 256 -2 0x3c \
				-3 128 -o $IAA_OPCODE_RLE_BURST -t 5000 "${VERBOSE}" $DEV_OPT
			"$IAATEST" -w "$wq_mode_code" -f "$flag" -l 512 -2 0x3c \
				-3 256 -o $IAA_OPCODE_RLE_BURST -t 5000 "${VERBOSE}" $DEV_OPT
			"$IAATEST" -w "$wq_mode_code" -f "$flag" -l 1024 -2 0x3c \
				-3 512 -o $IAA_OPCODE_RLE_BURST -t 5000 "${VERBOSE}" $DEV_OPT

			"$IAATEST" -w "$wq_mode_code" -f "$flag" -l 64 -2 0x7c \
				-3 16 -o $IAA_OPCODE_RLE_BURST -t 5000 "${VERBOSE}" $DEV_OPT
			"$IAATEST" -w "$wq_mode_code" -f "$flag" -l 128 -2 0x7c \
				-3 32 -o $IAA_OPCODE_RLE_BURST -t 5000 "${VERBOSE}" $DEV_OPT
			"$IAATEST" -w "$wq_mode_code" -f "$flag" -l 256 -2 0x7c \
				-3 64 -o $IAA_OPCODE_RLE_BURST -t 5000 "${VERBOSE}" $DEV_OPT
			"$IAATEST" -w "$wq_mode_code" -f "$flag" -l 512 -2 0x7c \
				-3 128 -o $IAA_OPCODE_RLE_BURST -t 5000 "${VERBOSE}" $DEV_OPT
			"$IAATEST" -w "$wq_mode_code" -f "$flag" -l 1024 -2 0x7c \
				-3 256 -o $IAA_OPCODE_RLE_BURST -t 5000 "${VERBOSE}" $DEV_OPT
			"$IAATEST" -w "$wq_mode_code" -f "$flag" -l 2048 -2 0x7c \
				-3 512 -o $IAA_OPCODE_RLE_BURST -t 5000 "${VERBOSE}" $DEV_OPT
		fi

		if [ $((IAA_OPCODE_MASK_FIND_UNIQUE & OP_CAP2)) -ne 0 ]; then
			"$IAATEST" -w "$wq_mode_code" -f "$flag" -l 512 -2 0x38 \
				-3 256 -o $IAA_OPCODE_FIND_UNIQUE -t 5000 "${VERBOSE}" $DEV_OPT
			"$IAATEST" -w "$wq_mode_code" -f "$flag" -l 1024 -2 0x38 \
				-3 512 -o $IAA_OPCODE_FIND_UNIQUE -t 5000 "${VERBOSE}" $DEV_OPT
			"$IAATEST" -w "$wq_mode_code" -f "$flag" -l 4096 -2 0x38 \
				-3 2048 -o $IAA_OPCODE_FIND_UNIQUE -t 5000 "${VERBOSE}" $DEV_OPT
			"$IAATEST" -w "$wq_mode_code" -f "$flag" -l 65536 -2 0x38 \
				-3 32768 -o $IAA_OPCODE_FIND_UNIQUE -t 5000 "${VERBOSE}" $DEV_OPT
			"$IAATEST" -w "$wq_mode_code" -f "$flag" -l 1048576 -2 0x38 \
				-3 524288 -o $IAA_OPCODE_FIND_UNIQUE -t 5000 "${VERBOSE}" $DEV_OPT
			"$IAATEST" -w "$wq_mode_code" -f "$flag" -l 2097152 -2 0x38 \
				-3 1048576 -o $IAA_OPCODE_FIND_UNIQUE -t 5000 "${VERBOSE}" $DEV_OPT
		fi

		if [ $((IAA_OPCODE_MASK_EXPAND & OP_CAP2)) -ne 0 ]; then
			"$IAATEST" -w "$wq_mode_code" -f "$flag" -l 512 -2 0x7c \
				-3 128 -o $IAA_OPCODE_EXPAND -t 5000 "${VERBOSE}" $DEV_OPT
			"$IAATEST" -w "$wq_mode_code" -f "$flag" -l 1024 -2 0x7c \
				-3 256 -o $IAA_OPCODE_EXPAND -t 5000 "${VERBOSE}" $DEV_OPT
			"$IAATEST" -w "$wq_mode_code" -f "$flag" -l 4096 -2 0x7c \
				-3 1024 -o $IAA_OPCODE_EXPAND -t 5000 "${VERBOSE}" $DEV_OPT
			"$IAATEST" -w "$wq_mode_code" -f "$flag" -l 65536 -2 0x7c \
				-3 16384 -o $IAA_OPCODE_EXPAND -t 5000 "${VERBOSE}" $DEV_OPT
			"$IAATEST" -w "$wq_mode_code" -f "$flag" -l 1048576 -2 0x7c \
				-3 262144 -o $IAA_OPCODE_EXPAND -t 5000 "${VERBOSE}" $DEV_OPT
			"$IAATEST" -w "$wq_mode_code" -f "$flag" -l 2097152 -2 0x7c \
				-3 524288 -o $IAA_OPCODE_EXPAND -t 5000 "${VERBOSE}" $DEV_OPT
		fi
	done
}

test_op_crypto()
{
	local opcode="$1"
	local flag="$2"
	local aecs_flag="$3"
	local op_name
	op_name=$(opcode2name "$opcode")
	local wq_mode_code
	local wq_mode_name

	for wq_mode_code in 0 1; do
		wq_mode_name=$(wq_mode2name "$wq_mode_code")
		echo "Performing $wq_mode_name WQ $op_name testing"
		for xfer_size in $SIZE_4K $SIZE_64K $SIZE_1M $SIZE_2M; do
			echo "Testing $xfer_size bytes"

			"$IAATEST" -w "$wq_mode_code" -l "$xfer_size" -o "$opcode" \
				-f "$flag" -a "$aecs_flag" -t 5000 "${VERBOSE}" $DEV_OPT
		done
	done
}

test_op_transl_fetch()
{
	local opcode="$1"
	local flag="$2"
	local op_name
	op_name=$(opcode2name "$opcode")
	local wq_mode_code
	local wq_mode_name

	for wq_mode_code in 0 1; do
		wq_mode_name=$(wq_mode2name "$wq_mode_code")
		echo "Performing $wq_mode_name WQ $op_name testing"
		for xfer_size in $SIZE_1 $SIZE_4K $SIZE_64K $SIZE_1M $SIZE_2M; do
			echo "Testing $xfer_size bytes"

			"$IAATEST" -w "$wq_mode_code" -l "$xfer_size" -o "$opcode" \
				-f "$flag" -t 5000 "${VERBOSE}" $DEV_OPT
		done
	done
}

if test -z "${SKIPCONFIG}"; then
	_cleanup
	start_iaa
	enable_wqs
fi

# shellcheck disable=SC2034
rc="$EXIT_FAILURE"

if [ $((IAA_OPCODE_MASK_NOOP & OP_CAP0)) -ne 0 ]; then
	flag="0x1"
	echo "Testing with 'block on fault' flag ON"
	test_op $IAA_OPCODE_NOOP $flag

	flag="0x0"
	echo "Testing with 'block on fault' flag OFF"
	test_op $IAA_OPCODE_NOOP $flag
fi

if [ $((IAA_OPCODE_MASK_CRC64 & OP_CAP2)) -ne 0 ]; then
	flag="0x1"
	extra_flag="0x8000"
	echo "Testing with 'block on fault' flag ON"
	test_op $IAA_OPCODE_CRC64 $flag $extra_flag

	flag="0x0"
	extra_flag="0x4000"
	echo "Testing with 'block on fault' flag OFF"
	test_op $IAA_OPCODE_CRC64 $flag $extra_flag
fi

unset SIZE_1

if [ $((IAA_OPCODE_MASK_ZCOMPRESS16 & OP_CAP2)) -ne 0 ]; then
	flag="0x1"
	echo "Testing with 'block on fault' flag ON"
	test_op $IAA_OPCODE_ZCOMPRESS16 $flag

	flag="0x0"
	echo "Testing with 'block on fault' flag OFF"
	test_op $IAA_OPCODE_ZCOMPRESS16 $flag
fi

if [ $((IAA_OPCODE_MASK_ZDECOMPRESS16 & OP_CAP2)) -ne 0 ]; then
	flag="0x1"
	echo "Testing with 'block on fault' flag ON"
	test_op $IAA_OPCODE_ZDECOMPRESS16 $flag

	flag="0x0"
	echo "Testing with 'block on fault' flag OFF"
	test_op $IAA_OPCODE_ZDECOMPRESS16 $flag
fi

if [ $((IAA_OPCODE_MASK_ZCOMPRESS32 & OP_CAP2)) -ne 0 ]; then
	flag="0x1"
	echo "Testing with 'block on fault' flag ON"
	test_op $IAA_OPCODE_ZCOMPRESS32 $flag

	flag="0x0"
	echo "Testing with 'block on fault' flag OFF"
	test_op $IAA_OPCODE_ZCOMPRESS32 $flag
fi

if [ $((IAA_OPCODE_MASK_ZDECOMPRESS32 & OP_CAP2)) -ne 0 ]; then
	flag="0x1"
	echo "Testing with 'block on fault' flag ON"
	test_op $IAA_OPCODE_ZDECOMPRESS32 $flag

	flag="0x0"
	echo "Testing with 'block on fault' flag OFF"
	test_op $IAA_OPCODE_ZDECOMPRESS32 $flag
fi

if [ $((IAA_OPCODE_MASK_COMPRESS & OP_CAP2)) -ne 0 ]; then
	flag="0x1"
	echo "Testing with 'block on fault' flag ON"
	test_op $IAA_OPCODE_COMPRESS $flag

	flag="0x0"
	echo "Testing with 'block on fault' flag OFF"
	test_op $IAA_OPCODE_COMPRESS $flag
fi

if [ $((IAA_OPCODE_MASK_DECOMPRESS & OP_CAP2)) -ne 0 ]; then
	flag="0x1"
	echo "Testing with 'block on fault' flag ON"
	test_op $IAA_OPCODE_DECOMPRESS $flag

	flag="0x0"
	echo "Testing with 'block on fault' flag OFF"
	test_op $IAA_OPCODE_DECOMPRESS $flag
fi

if [ $((IAA_OPCODE_MASK_ZCOMPRESS8 & OP_CAP2)) -ne 0 ]; then
	flag="0x1"
	echo "Testing with 'block on fault' flag ON"
	test_op $IAA_OPCODE_ZCOMPRESS8 $flag

	flag="0x0"
	echo "Testing with 'block on fault' flag OFF"
	test_op $IAA_OPCODE_ZCOMPRESS8 $flag
fi

if [ $((IAA_OPCODE_MASK_ZDECOMPRESS8 & OP_CAP2)) -ne 0 ]; then
	flag="0x1"
	echo "Testing with 'block on fault' flag ON"
	test_op $IAA_OPCODE_ZDECOMPRESS8 $flag

	flag="0x0"
	echo "Testing with 'block on fault' flag OFF"
	test_op $IAA_OPCODE_ZDECOMPRESS8 $flag
fi

flag="0x1"
test_op_filter $flag

flag="0x0"
test_op_filter $flag

if [ $((IAA_OPCODE_MASK_ENCRYPT & OP_CAP2)) -ne 0 ]; then
	flag="0x1"
	aecs_flag="0x0101"
	echo "Testing with 'block on fault' flag ON"
	test_op_crypto $IAA_OPCODE_ENCRYPT $flag $aecs_flag

	flag="0x0"
	aecs_flag="0x0301"
	echo "Testing with 'block on fault' flag OFF"
	test_op_crypto $IAA_OPCODE_ENCRYPT $flag $aecs_flag
fi

if [ $((IAA_OPCODE_MASK_DECRYPT & OP_CAP2)) -ne 0 ]; then
	flag="0x1"
	aecs_flag="0x0101"
	echo "Testing with 'block on fault' flag ON"
	test_op_crypto $IAA_OPCODE_DECRYPT $flag $aecs_flag

	flag="0x0"
	aecs_flag="0x0301"
	echo "Testing with 'block on fault' flag OFF"
	test_op_crypto $IAA_OPCODE_DECRYPT $flag $aecs_flag
fi

if [ $((IAA_OPCODE_MASK_TRANSL_FETCH & OP_CAP0)) -ne 0 ]; then
	flag="0x1"
	echo "Testing with 'block on fault' flag ON"
	test_op_transl_fetch $IAA_OPCODE_TRANSL_FETCH $flag

	flag="0x0"
	echo "Testing with 'block on fault' flag OFF"
	test_op_transl_fetch $IAA_OPCODE_TRANSL_FETCH $flag
fi

if test -z "${SKIPCONFIG}"; then
	disable_wqs
	stop_iaa
	_cleanup
fi

exit 0
