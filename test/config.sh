#!/bin/bash -Ex

# SPDX-License-Identifier: GPL-2.0
# Copyright(c) 2018, FUJITSU LIMITED. All rights reserved.

rc=77
config_pid=65536
logfile=""
conf_file=""
config_dimms=""
config_regions=""
config_namespace=""
smart_supported_bus=""

. ./common

trap 'err $LINENO' ERR

check_min_kver "4.15" || do_skip "kernel $KVER may not support config service"

init()
{
	$DSACTL disable-region -b $NFIT_TEST_BUS0 all
	$DSACTL zero-labels -b $NFIT_TEST_BUS0 all
	$DSACTL enable-region -b $NFIT_TEST_BUS0 all
}

start_config()
{
	logfile=$(mktemp)
	$DSACTL config -l $logfile $1 &
	config_pid=$!
	sync; sleep 3
	truncate --size 0 $logfile #remove startup log
}

set_smart_supported_bus()
{
	smart_supported_bus=$NFIT_TEST_BUS0
	config_dimms=$(./list-smart-dimm -b $smart_supported_bus | jq -r .[0].dev)
	if [ -z $config_dimms ]; then
		smart_supported_bus=$NFIT_TEST_BUS1
	fi
}

get_config_dimm()
{
	jlist=$(./list-smart-dimm -b $smart_supported_bus $1)
	config_dimms=$(jq '.[]."dev"?, ."dev"?' <<<$jlist | sort | uniq | xargs)
	echo $config_dimms
}

call_notify()
{
	./smart-notify $smart_supported_bus
	sync; sleep 3
}

inject_smart()
{
	$DSACTL inject-smart $config_dimms $1
	sync; sleep 3
}

check_result()
{
	jlog=$(cat $logfile)
	notify_dimms=$(jq ."dimm"."dev" <<<$jlog | sort | uniq | xargs)
	[[ $1 == $notify_dimms ]]
}

stop_config()
{
	kill $config_pid
	rm $logfile
}

test_filter_dimm()
{
	config_dimms=$(get_config_dimm | awk '{print $1}')
	start_config "-d $config_dimms"
	call_notify
	check_result "$config_dimms"
	stop_config
}

test_filter_bus()
{
	config_dimms=$(get_config_dimm)
	start_config "-b $smart_supported_bus"
	call_notify
	check_result "$config_dimms"
	stop_config
}

test_filter_region()
{
	count=$($DSACTL list -R -b $smart_supported_bus | jq -r .[].dev | wc -l)
	i=0
	while [ $i -lt $count ]; do
		config_region=$($DSACTL list -R -b $smart_supported_bus | jq -r .[$i].dev)
		config_dimms=$(get_config_dimm "-r $config_region")
		[ ! -z $config_dimms ] && break
		i=$((i + 1))
	done
	start_config "-r $config_region"
	call_notify
	check_result "$config_dimms"
	stop_config
}

test_filter_namespace()
{
	init
	config_namespace=$($DSACTL create-namespace -b $smart_supported_bus | jq -r .dev)
	config_dimms=$(get_config_dimm "-n $config_namespace")
	start_config "-n $config_namespace"
	call_notify
	check_result "$config_dimms"
	stop_config
	$DSACTL destroy-namespace $config_namespace -f
}

test_conf_file()
{
	config_dimms=$(get_config_dimm)
	conf_file=$(mktemp)
	echo "dimm = $config_dimms" > $conf_file
	start_config "-c $conf_file"
	call_notify
	check_result "$config_dimms"
	stop_config
	rm $conf_file
}

test_filter_dimmevent()
{
	config_dimms="$(get_config_dimm | awk '{print $1}')"

	start_config "-d $config_dimms -D dimm-unclean-shutdown"
	inject_smart "-U"
	check_result "$config_dimms"
	stop_config

	inject_value=$($DSACTL list -H -d $config_dimms | jq -r .[]."health"."spares_threshold")
	inject_value=$((inject_value - 1))
	start_config "-d $config_dimms -D dimm-spares-remaining"
	inject_smart "-s $inject_value"
	check_result "$config_dimms"
	stop_config

	inject_value=$($DSACTL list -H -d $config_dimms | jq -r .[]."health"."temperature_threshold")
	inject_value=$((inject_value + 1))
	start_config "-d $config_dimms -D dimm-media-temperature"
	inject_smart "-m $inject_value"
	check_result "$config_dimms"
	stop_config
}

do_tests()
{
	test_filter_dimm
	test_filter_bus
	test_filter_region
	test_filter_namespace
	test_conf_file
	test_filter_dimmevent
}

modprobe nfit_test
rc=1
init
set_smart_supported_bus
do_tests
_cleanup
exit 0
