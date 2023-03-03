#!/bin/bash -Ex
# SPDX-License-Identifier: GPL-2.0
# Copyright(c) 2019-2020 Intel Corporation. All rights reserved.

. "$(dirname "$0")/common"

DSA=dsa0
WQ0=wq0.0
GRP0=group0.0
ENG0=engine0.0
IDXD_DEVICE_PATH=/sys/bus/dsa/devices

[ ! -f "$DSATEST" ] && echo "fail: $LINENO" && exit 1

check_min_kver "5.6" || do_skip "kernel does not support idxd"

# skip if no pasid support as dsa_test does not support operation w/o pasid yet.
[ ! -f "/sys/bus/dsa/devices/$DSA/pasid_enabled" ] && echo "No SVM support" && exit "$EXIT_SKIP"

pasid_en=$(cat /sys/bus/dsa/devices/$DSA/pasid_enabled)
if [ "$pasid_en" -ne 1 ]; then
	exit "$EXIT_SKIP"
fi

IDXD_VERSION=$(cat /sys/bus/dsa/devices/dsa0/version)

# Test accel-config configure attributes of a group
# 1 config command error
# 0 config successfully
group_config_test()
{
	local read_ret

	if [ -f "$IDXD_DEVICE_PATH/$DSA/$GRP0/read_buffers_allowed" ]; then
		# config read_buffers
		"$ACCFG" config-group $DSA/$GRP0 -r 37 || exit 1
		read_ret=$(cat $IDXD_DEVICE_PATH/$DSA/$GRP0/read_buffers_reserved)
		if [ "$read_ret" -ne 37 ]; then
			echo "config group read-buffers-reserved failed" && exit "$EXIT_FAILURE"
		fi
		"$ACCFG" config-group $DSA/$GRP0 --read-buffers-reserved 0 || exit 1

		"$ACCFG" config-group $DSA/$GRP0 -t 28 || exit 1
		read_ret=$(cat $IDXD_DEVICE_PATH/$DSA/$GRP0/read_buffers_allowed)
		if [ "$read_ret" -ne 28 ]; then
			echo "config group read_buffers_allowed failed" && exit "$EXIT_FAILURE"
		fi
		"$ACCFG" config-group $DSA/$GRP0 --read-buffers-allowed 0 || exit 1

		"$ACCFG" config-device -l 11 $DSA
		"$ACCFG" config-group $DSA/$GRP0 -l 1 || exit 1
		read_ret=$(cat $IDXD_DEVICE_PATH/$DSA/$GRP0/use_read_buffer_limit)
		if [ "$read_ret" -ne 1 ]; then
			echo "config group use_read_buffer_limit failed" && exit "$EXIT_FAILURE"
		fi
		"$ACCFG" config-group $DSA/$GRP0 --use-read-buffer-limit 0 || exit 1
		"$ACCFG" config-device -l 0 $DSA
	fi

	# Traffic class is set 1 for best performance
	# Not allow to config traffic class a and b

	# group descriptor in gregress limit
	if [ "$IDXD_VERSION" != "0x100" ]; then

		"$ACCFG" config-group $DSA/$GRP0 -d 3 || exit 1
		read_ret=$(cat $IDXD_DEVICE_PATH/$DSA/$GRP0/desc_progress_limit)
		if [ "$read_ret" -ne 3 ]; then
			echo "config group desc_progress_limit failed" && exit "$EXIT_FAILURE"
		fi
		"$ACCFG" config-group $DSA/$GRP0 -d 1 || exit 1
		read_ret=$(cat $IDXD_DEVICE_PATH/$DSA/$GRP0/desc_progress_limit)
		if [ "$read_ret" -ne 1 ]; then
			echo "config group desc_progress_limit failed" && exit "$EXIT_FAILURE"
		fi
		"$ACCFG" config-group $DSA/$GRP0 --desc-progress-limit 0 || exit 1

		"$ACCFG" config-group $DSA/$GRP0 -p 2 || exit 1
		read_ret=$(cat $IDXD_DEVICE_PATH/$DSA/$GRP0/batch_progress_limit)
		if [ "$read_ret" -ne 2 ]; then
			echo "config group batch_progress_limit failed" && exit "$EXIT_FAILURE"
		fi
		"$ACCFG" config-group $DSA/$GRP0 -p 1 || exit 1
		read_ret=$(cat $IDXD_DEVICE_PATH/$DSA/$GRP0/batch_progress_limit)
		if [ "$read_ret" -ne 1 ]; then
			echo "config group batch_progress_limit failed" && exit "$EXIT_FAILURE"
		fi
		"$ACCFG" config-group $DSA/$GRP0 --batch-progress-limit 0 || exit 1
	fi
}

# Test accel-config configure attributes of an engine
# 1 config command error
# 0 config successfully
engine_config_test()
{
	local read_ret

	# config engine group id
	"$ACCFG" config-engine $DSA/$ENG0 -g 3 || exit 1
	read_ret=$(cat $IDXD_DEVICE_PATH/$DSA/$ENG0/group_id)
	if [ "$read_ret" -ne 3 ]; then
		echo "config engine group_id failed" && exit "$EXIT_FAILURE"
	fi
	"$ACCFG" config-engine $DSA/$ENG0 --group-id -1 || exit 1
}


# Test accel-config configure attributes of an work queue
# 1 config command error
# 0 config successfully
wq_config_test()
{
	local read_ret

	# config work queue mode
	"$ACCFG" config-wq $DSA/$WQ0 -m shared || exit 1
	read_ret=$(cat $IDXD_DEVICE_PATH/$DSA/$WQ0/mode)
	if [ "$read_ret" != "shared" ]; then
		echo "config wq shared mode failed" && exit "$EXIT_FAILURE"
	fi
	"$ACCFG" config-wq $DSA/$WQ0 --mode dedicated || exit 1
	read_ret=$(cat $IDXD_DEVICE_PATH/$DSA/$WQ0/mode)
	if [ "$read_ret" != "dedicated" ]; then
		echo "config wq dedicated mode failed" && exit "$EXIT_FAILURE"
	fi

	# config work queue size
	"$ACCFG" config-wq $DSA/$WQ0 -s 128 || exit 1
	read_ret=$(cat $IDXD_DEVICE_PATH/$DSA/$WQ0/size)
	if [ "$read_ret" -ne 128 ]; then
		echo "config wq size failed" && exit "$EXIT_FAILURE"
	fi
	"$ACCFG" config-wq $DSA/$WQ0 --wq-size 16 || exit 1

	# config work queue group id
	"$ACCFG" config-wq $DSA/$WQ0 -g 3 || exit 1
	read_ret=$(cat $IDXD_DEVICE_PATH/$DSA/$WQ0/group_id)
	if [ "$read_ret" -ne 3 ]; then
		echo "config wq group id failed" && exit "$EXIT_FAILURE"
	fi
	"$ACCFG" config-wq $DSA/$WQ0 -g -1 || exit 1

	# operaton config
	if [ "$IDXD_VERSION" != "0x100" ]; then
		[ ! -f "$IDXD_DEVICE_PATH/$DSA/$WQ0/op_config" ] && exit 1

		echo 0 > "$IDXD_DEVICE_PATH/$DSA/$WQ0/op_config"
		read_ret=$(cat $IDXD_DEVICE_PATH/$DSA/$WQ0/op_config | cut -c 55-)
		if [ "$read_ret" != "00000000,00000000"	]; then
			echo "wq op_config 0 failed" && exit "$EXIT_FAILURE"
		fi

		echo 238 > "$IDXD_DEVICE_PATH/$DSA/$WQ0/op_config"
		read_ret=$(cat $IDXD_DEVICE_PATH/$DSA/$WQ0/op_config | cut -c 55-)
		if [ "$read_ret" != "00000000,00000238" ]; then
			echo "wq op_config memory copy,fill,compare,
			dualcast failed" && exit "$EXIT_FAILURE"
		fi

		"$ACCFG" config-wq $DSA/$WQ0 -o 30 || exit 1
		read_ret=$(cat $IDXD_DEVICE_PATH/$DSA/$WQ0/op_config | cut -c 55-)
		if [ "$read_ret" != "00000000,00000030" ]; then
			echo "config wq op_config failed" && exit "$EXIT_FAILURE"
		fi

		"$ACCFG" config-wq $DSA/$WQ0 --op-config=00f800fb,00bf07ff || exit 1
		read_ret=$(cat $IDXD_DEVICE_PATH/$DSA/$WQ0/op_config | cut -c 55-)
		if [ "$read_ret" != "00f800fb,00bf07ff" ]; then
			echo "config wq full operations failed" && exit "$EXIT_FAILURE"
		fi

		"$ACCFG" config-wq $DSA/$WQ0 -g 0 -m dedicated -y user -n app1 -d user -p 10 -o 0
		"$ACCFG" config-engine $DSA/$ENG0 -g 0
		read_ret=$(cat $IDXD_DEVICE_PATH/$DSA/$WQ0/op_config | cut -c 55-)
		if [ "$read_ret" != "00000000,00000000" ]; then
			echo "wq op_config 0 failed" && exit "$EXIT_FAILURE"
		fi
		"$ACCFG" enable-device $DSA
		"$ACCFG" enable-wq $DSA/$WQ0
		"$DSATEST" -w 0 -l 4096 -f 0x1 -o 0x3 -v && echo "shoudl fail, but pass" && exit 1
		"$DSATEST" -w 0 -l 4096 -f 0x1 -o 0x1 -b 0x4 -c 2 &&
			echo "shoudl fail, but pass" && exit 1
		"$ACCFG" disable-device $DSA

		"$ACCFG" config-wq $DSA/$WQ0 -g 0 -m dedicated -y user -n app1 -d user -p 10 -o 8
		"$ACCFG" config-engine $DSA/$ENG0 -g 0
		read_ret=$(cat $IDXD_DEVICE_PATH/$DSA/$WQ0/op_config | cut -c 55-)
		if [ "$read_ret" != "00000000,00000008" ]; then
			echo "wq op_config 8 failed" && exit "$EXIT_FAILURE"
		fi
		"$ACCFG" enable-device $DSA
		"$ACCFG" enable-wq $DSA/$WQ0
		"$DSATEST" -w 0 -l 4096 -f 0x1 -o 0x3 || echo "shoudl pass, but fail" || exit 1
		"$DSATEST" -w 0 -l 4096 -f 0x1 -o 0x5 && echo "shoudl fail, but pass" && exit 1
		"$DSATEST" -w 0 -l 4096 -f 0x1 -o 0x1 -b 0x3 -c 2 &&
			echo "shoudl fail, but pass" && exit 1
		"$ACCFG" disable-device $DSA

		"$ACCFG" config-wq $DSA/$WQ0 -g 0 -m dedicated -y user -n app1 -d user -p 10 -o 272
		"$ACCFG" config-engine $DSA/$ENG0 -g 0
		read_ret=$(cat $IDXD_DEVICE_PATH/$DSA/$WQ0/op_config | cut -c 55-)
		if [ "$read_ret" != "00000000,00000272" ]; then
			echo "wq op_config 30 failed" && exit "$EXIT_FAILURE"
		fi
		"$ACCFG" enable-device $DSA
		"$ACCFG" enable-wq $DSA/$WQ0
		"$DSATEST" -w 0 -l 4096 -f 0x1 -o 0x0 && echo "shoudl fail, but pass" && exit 1
		"$DSATEST" -w 0 -l 4096 -f 0x1 -o 0x2 && echo "shoudl fail, but pass" && exit 1
		"$DSATEST" -w 0 -l 4096 -f 0x1 -o 0x3 && echo "shoudl fail, but pass" && exit 1
		"$DSATEST" -w 0 -l 4096 -f 0x1 -o 0x7 && echo "shoudl fail, but pass" && exit 1
		"$DSATEST" -w 0 -l 4096 -f 0x1 -o 0x8 && echo "shoudl fail, but pass" && exit 1
		"$DSATEST" -w 0 -l 4096 -f 0x1 -o 0x4 || echo "shoudl pass, but fail" || exit 1
		"$DSATEST" -w 0 -l 4096 -f 0x1 -o 0x5 || echo "shoudl pass, but fail" || exit 1
		"$DSATEST" -w 0 -l 4096 -f 0x1 -o 0x6 || echo "shoudl pass, but fail" || exit 1
		"$DSATEST" -w 0 -l 4096 -f 0x1 -o 0x9 || echo "shoudl fail, but pass" || exit 1
		"$DSATEST" -w 0 -l 4096 -f 0x1 -o 0x1 -b 0x5 -c 2 ||
			echo "shoudl pass, but fail" || exit 1
		"$DSATEST" -w 0 -l 4096 -f 0x1 -o 0x1 -b 0x9 -c 2 ||
			echo "shoudl pass, but fail" || exit 1
		"$ACCFG" disable-device $DSA
	fi
}

_cleanup

group_config_test
engine_config_test
wq_config_test

_cleanup
exit 0
