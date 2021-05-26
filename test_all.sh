#!/bin/bash

batch=0,0,0,0
batch_cpf=1,0,0,0
success=0,0,0,0
page_fault=1,0,0,0
cp_error_log=0,1,0,0
cp_wr_fail=0,1,1,0
fence=0,0,0,1
page_fault_cp_error_log=1,1,0,0
page_fault_cp_write_fail=1,1,1,0
da_page_fault=0,0,1,2
da_page_bc_fault=1,0,1,2

run_dsa_test() {

	echo $1
	echo $2
	./test/.libs/dsa_test -o1 -b3 -w0 -f0x8 -c$1 -e$2
}

#1a-1.0
#eval declare -a param=('"'$batch':'$success':'$cp_error_log'"'\				#1a
#			'"'$batch':'$success':'$cp_wr_fail'"'\				#1a
#			'"'$batch':'$cp_error_log':'$fence'"'\				#1b
#			'"'$batch':'$page_fault':'$cp_error_log'"'\			#2a
#			'"'$batch':'$page_fault':'$cp_error_log':'$fence'"'\		#2b
#			'"'$batch':'$success':'$page_fault_cp_error_log':'$fence'"'\	#3.0
#			'"'$batch':'$success':'$page_fault_cp_write_fail':'$fence'"'\	#3.1
#			'"'$batch_cpf':'$success':'$cp_error_log'"'\			#4a.0
#			'"'$batch_cpf':'$success':'$cp_wr_fail'"')			#4a.1
#			'"'$batch_cpf':'$success':'$success'"')
#			'"'$da_page_fault':'$success':'$success':'$success'"'\		#6a
#			'"'$da_page_bc_fault':'$success':'$success':'$success'"'\	#6b
#			'"'$da_page_fault':'$success':'$cp_error_log':'$success'"'\	#6c
#			'"'$da_page_fault':'$page_fault':'$cp_error_log':'$success'"'\	#6d.0
#			'"'$da_page_fault':'$page_fault':'$cp_wr_fail':'$success'"')	#6d.1

eval declare -a param=('"'$batch':'$success':'$cp_error_log'"'				#1a.0
			'"'$batch':'$success':'$cp_wr_fail'"'				#1a.1
			'"'$batch':'$success':'$cp_error_log':'$fence'"'		#1b
			'"'$batch':'$page_fault':'$cp_error_log'"'			#2a
			'"'$batch':'$page_fault':'$cp_error_log':'$fence'"'		#2b
			'"'$batch':'$success':'$page_fault_cp_error_log':'$fence'"'	#3.0
			'"'$batch':'$success':'$page_fault_cp_write_fail':'$fence'"'	#3.1
			'"'$batch_cpf':'$success':'$cp_error_log'"'			#4a.0
			'"'$batch_cpf':'$success':'$cp_wr_fail'"'			#4a.1
			'"'$batch_cpf':'$success':'$success'"'				#4b
			'"'$da_page_fault':'$success':'$success':'$success'"'		#6a
			'"'$da_page_bc_fault':'$success':'$success':'$success'"'	#6b
			'"'$da_page_fault':'$success':'$cp_error_log':'$success'"'	#6c.0
			'"'$da_page_fault':'$success':'$cp_wr_fail':'$success'"'	#6c.1
			'"'$da_page_fault':'$page_fault':'$cp_error_log':'$success'"'	#6d.0
			'"'$da_page_fault':'$page_fault':'$cp_wr_fail':'$success'"')	#6d.1

eval declare -a casename=(1a.0
			 1a.1
			 1b
			 2a
			 2b
			 3.0
			 3.1
			 4a.0
			 4a.1
			 4b
			 6a
			 6b
			 6c.0
			 6c.1
			 6d.0
			 6d.1)

run_all() {
	l=${#param[@]}
	for ((i=0;i<l;i++));
	do
		echo ""
		echo "Running case" ${casename[$i]}

		n=`echo "${param[$i]}" | awk -F\: '{print NF-1}'`
		run_dsa_test $n ${param[$i]}
	done
}

run_one() {
	l=${#param[@]}
	for ((i=0;i<l;i++));
	do
		if [ "$1" == "${casename[$i]}" ]; then
			echo "Running case" ${casename[$i]}

			n=`echo "${param[$i]}" | awk -F\: '{print NF-1}'`
			run_dsa_test $n ${param[$i]}
		fi
	done
}

if [ $# -eq 1 ]; then
	run_one $1
else
	run_all
fi
