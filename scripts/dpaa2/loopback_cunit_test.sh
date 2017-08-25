#/*
# * Copyright (c) 2015-2016 Freescale Semiconductor, Inc. All rights reserved.
# * Copyright (c) 2017 NXP
# */

help() {
	echo
	echo "USAGE: . ./loopback_cunit_test.sh <options>
The Options are:
	-a			Auto mode		Enabling the Auto mode. Default is manual
							mode.

	--cunit-path=\"path\"	Cunit binaries path	'path' is absolute path of cunit applications.

	-d			Developer help		This option is only for developers. It will
							print the help for developers, which describes
							how to add a test case in the script.

	-h			Help			Prints script help.

Example:
	. ./loopback_cunit_test.sh -a        OR     source ./loopback_cunit_test.sh -a

Assumptions:
	* dynamic_dpl.sh and loopback_cunit_test.sh all these scripts are present in the
	  '/usr/local/odp/scripts' directory.
	* All ODP Cunit binaries are present in the '/usr/local/odp/test/validation' directory.

Note:	Minimum running time of script for all test cases is 10 mins.
	"

}

developer_help() {
	echo
	echo -e "\tDeveloper's Help:

	###############################################################################
	############ Cunit script will have following Resources ######################
	###############################################################################
	One container will be created for the testing, having 2 DPNIs objects:

	One DPNI will be a dummy DPNI and other will be a loopback device.


				       CDPNI1 (loop device)
                                         /\
					 \/
				====================
				|      CDPRC       |
				|	           |
				====================
				   CDPNI0 |
				(Dummy IF)|
				       

Method to add a Cunit application as test case:

Test case command syntax:
	run_cunit_command <argument>

	Where argument is actual command to run.
	CDPRC will be used for CUNIT testing

Example:

	run_cunit_command \"./init_main_ok\"

	This command should only be added in run_cunit() function.

Results:
	Cunit results will be based on the failed test_suites/test_cases showing in the application logs
	"
}

#/* Function to append new lines into sanity_log file*/
append_newline() {
	num=0
	while [[ $num -lt $1 ]]
	do
		echo >> sanity_log
		num=`expr $num + 1`
	done
}

#Checking if resources are already available
check_resources() {
	#checking Cunit script containers
	if [[ -z $CDPRC ]]
	then
		return 1;
	fi

	return 0;
}

#creating the required resources
get_resources() {
	export DPIO_COUNT=20
	export DPBP_COUNT=20
	export DPCI_COUNT=128

	#/*
	# * creating the container "CDPRC" with 3 DPNIs out of which 2 will be connected to
	# * each other and one is loopback device.
	# */
	. ./dynamic_dpl.sh dpni
	CDPRC=$DPRC

	#/* Note: no need to store the loopback device. Application will auto detect the device.*/
}

run_cunit_command() {
	MODULE=`echo "$1" | grep -o "\w*_\w*"| sed -e 's/_main//g'`
	echo -e " #$cunit_test_no)\tTest case:$MODULE\t\tCommand:($1)"
	echo
	eval $PRINT_MSG
	$READ
	echo
	if [[ "$input" == "y" ]]
	then
		echo -e " #$cunit_test_no)\tTest case:$MODULE\t\tCommand:($1)" >> cunit_log
		if [[ ! -e "$1" ]]
		then
			echo -e " #$cunit_test_no)\tTest case:$MODULE\t\tCommand:($1)" >> cunit_untested_app
			echo -e "\t$1 File doesn't exist" | tee -a cunit_log
			echo -e $RED"\tNot tested"$NC
			echo -e "\t[NT] Not tested" >> cunit_untested_app
			cunit_untested=`expr $cunit_untested + 1`
			cunit_test_no=`expr $cunit_test_no + 1`
			echo >> cunit_untested_app
			echo >> cunit_untested_app
			echo >> cunit_log
			echo >> cunit_log
			echo
			echo
			return;
		fi
		eval "$1 > log 2>&1 &"
		if [[ $MODULE == "time" ||
			$MODULE == "system" ]]
		then
			sleep 40
		else
			sleep 10
		fi
		killall -s SIGKILL $1 > /dev/null 2>&1
		sleep 2
		echo
		echo -e " #$cunit_test_no)\tTest case:$MODULE\t\tCommand:($1)" >> cunit_tested_app
		echo >> cunit_tested_app
		sed -n '/^Run Summary/,/^Elapsed/p' log | tee temp_log
		suite_failed_no=`awk '{$2=$2};1' temp_log | cut -f5 -d ' ' | tr -s '\n' ' ' |  cut -f2 -d ' '`
		test_failed_no=`awk '{$2=$2};1' temp_log | cut -f5 -d ' ' | tr -s '\n' ' ' |  cut -f3 -d ' '`
		echo >> cunit_tested_app
		if [[ (! $suite_failed_no) && (! $test_failed_no) ]]
		then
			echo -e "\t[UR] Unknown result" >> cunit_tested_app
			echo -e $RED"\tUnknown result " $NC
			cunit_na=`expr $cunit_na + 1`
		elif [[ $suite_failed_no != 0 || $test_failed_no != 0 ]]
		then
			if [[ $test_failed_no != 0 ]]
			then
				echo -e "\t[FAILED] Number of FAILED tests = "$test_failed_no >> cunit_tested_app
				echo -e $RED"\tNumber of FAILED tests= "$test_failed_no $NC
			else
				echo -e "\t[FAILED] Number of FAILED suites = "$suite_failed_no >> cunit_tested_app
				echo -e $RED"\tNumber of FAILED suites = "$suite_failed_no $NC
			fi
			cunit_failed=`expr $cunit_failed + 1`
		else
			echo -e "\t[PASSED] CUNIT test module '$MODULE' is PASSED " >> cunit_tested_app
			echo -e $GREEN"\tCUNIT test module '$MODULE' is PASSED " $NC
			cunit_passed=`expr $cunit_passed + 1`
		fi

		echo >> cunit_tested_app
		echo >> cunit_tested_app
		cat log >> cunit_log
		echo >> cunit_log
		echo >> cunit_log
		echo
		echo
		rm log
		rm temp_log
	else
		echo -e " #$cunit_test_no)\tTest case:$MODULE\t\tCommand:($1)" >> cunit_untested_app
		echo -e "\tNot tested" >> cunit_untested_app
		echo -e $RED"\tNot tested" $NC
		cunit_untested=`expr $cunit_untested + 1`
		echo >> cunit_untested_app
		echo >> cunit_untested_app
		echo
		echo
	fi
	cunit_test_no=`expr $cunit_test_no + 1`
}


#function to run CUNIT
run_cunit() {
	run_cunit_command "./init_main_ok"
	run_cunit_command "./init_main_log"
	run_cunit_command "./init_main_abort"
	run_cunit_command "./queue_main"
	run_cunit_command "./buffer_main"
	run_cunit_command "./classification_main"
	run_cunit_command "./cpumask_main"
	run_cunit_command "./crypto_main"
	run_cunit_command "./proto_main"
	run_cunit_command "./errno_main"
	run_cunit_command "./packet_main"
	run_cunit_command "./pktio_main"
	run_cunit_command "./pool_main"
	run_cunit_command "./random_main"
	run_cunit_command "./scheduler_main"
	run_cunit_command "./shmem_main"
	run_cunit_command "./system_main"
	run_cunit_command "./thread_main"
	run_cunit_command "./time_main"
	run_cunit_command "./timer_main"
	run_cunit_command "./atomic_main"
	run_cunit_command "./barrier_main"
	run_cunit_command "./hash_main"
	run_cunit_command "./lock_main"
	run_cunit_command "./std_clib_main"
	run_cunit_command "./traffic_mngr_main"
}

main() {
	cd $CUNIT_PATH
	if [[ $CUNIT_AUTO_INPUT != y ]]
	then
		PRINT_MSG="echo -e \"\tEnter 'y' to execute the test case\""
		READ="read input"
	else
		PRINT_MSG=
		READ=
		input=y
	fi
	export DPRC=$CDPRC
	run_cunit

	echo "############################################## TEST REPORT ################################################" >> result
	echo >> result
	echo >> result
	echo -e "\tCUNIT:" >> result
	echo >> result
	echo -e "\tNo. of passed CUNIT test modules		\t\t= $cunit_passed" >> result
	echo -e "\tNo. of failed CUNIT test modules		\t\t= $cunit_failed" >> result
	echo -e "\tNo. of untested CUNIT test modules		\t\t= $cunit_untested" >> result
	echo -e "\tNo. of CUNIT test modules with unknown results	\t\t= $cunit_na" >> result
	echo -e "\tTotal number CUNIT test modules			\t\t= `expr $cunit_test_no - 1`" >> result
	echo >> result
	mv $CUNIT_PATH/cunit_log $ODP_PATH/scripts/cunit_log
	echo >> $ODP_PATH/scripts/sanity_log
	echo "#################################################### CUNIT ##############################################" >> $ODP_PATH/scripts/sanity_log
	echo >> $ODP_PATH/scripts/sanity_log
	cat $ODP_PATH/scripts/cunit_log >> $ODP_PATH/scripts/sanity_log
	rm $ODP_PATH/scripts/cunit_log
	if [[ -e "$CUNIT_PATH/cunit_tested_app" ]]
	then
		mv $CUNIT_PATH/cunit_tested_app $ODP_PATH/scripts/cunit_tested_app
		echo >> $ODP_PATH/scripts/sanity_tested_apps
		echo "#################################################### CUNIT ##############################################" >> $ODP_PATH/scripts/sanity_tested_apps
		echo >> $ODP_PATH/scripts/sanity_tested_apps
		cat $ODP_PATH/scripts/cunit_tested_app >> $ODP_PATH/scripts/sanity_tested_apps
		rm $ODP_PATH/scripts/cunit_tested_app
	fi
	if [[ -e "$CUNIT_PATH/cunit_untested_app" ]]
	then
		mv $CUNIT_PATH/cunit_untested_app $ODP_PATH/scripts/cunit_untested_app
		echo >> $ODP_PATH/scripts/sanity_untested_apps
		echo "#################################################### CUNIT ##############################################" >> $ODP_PATH/scripts/sanity_untested_apps
		echo >> $ODP_PATH/scripts/sanity_untested_apps
		cat $ODP_PATH/scripts/cunit_untested_app >> $ODP_PATH/scripts/sanity_untested_apps
		rm $ODP_PATH/scripts/cunit_untested_app
	fi
	echo
	cat result
	echo
	echo >> result
	echo -e "NOTE:  Test results are based on applications logs, If there is change in any application log, results may go wrong.
\tSo it is always better to see console log and sanity_log to verify the results." >> result
	echo >> result
	cat result > $ODP_PATH/scripts/sanity_test_report
	rm result
	echo
	echo
	echo -e " COMPLETE LOG			=> $GREEN $ODP_PATH/scripts/sanity_log $NC"
	echo
	echo -e " SANITY TESTED APPS REPORT	=> "$GREEN"$ODP_PATH/scripts/sanity_tested_apps"$NC
	echo
	echo -e " SANITY UNTESTED APPS		=> "$GREEN"$ODP_PATH/scripts/sanity_untested_apps"$NC
	echo
	echo -e " SANITY REPORT			=> "$GREEN"$ODP_PATH/scripts/sanity_test_report"$NC
	echo
	echo " Sanity testing is Done."
	echo
	cd -
}


# script's starting point
set -m

if [ -e /sys/firmware/devicetree/base/compatible ]
then
	board=`grep -ao 'ls1088\|ls2088\|ls2080\|ls2085\|lx2160' /sys/firmware/devicetree/base/compatible | head -1`
fi

input=
cunit_test_no=1
cunit_passed=0
cunit_failed=0
cunit_na=0
cunit_untested=0
CUNIT=0
if [[ -z $ODP_PATH ]]
then
	ODP_PATH="/usr/local/odp"
fi
if [[ -z $CUNIT_PATH ]]
then
	CUNIT_PATH="$ODP_PATH/test/validation"
fi
CUNIT_AUTO_INPUT=


#/*
# * Parsing the arguments.
# */
if [[ $1 ]]
then
	for i in "$@"
	do
		case $i in
			-h)
				help
				[[ "${BASH_SOURCE[0]}" != $0 ]] && return || exit
				;;
			-d)
				developer_help
				[[ "${BASH_SOURCE[0]}" != $0 ]] && return || exit
				;;
			-a)
				CUNIT_AUTO_INPUT=y
				;;
			--cunit-path=*)
				CUNIT_PATH="${i#*=}"
				;;
			*)
				echo "Invalid option $i"
				help
				[[ "${BASH_SOURCE[0]}" != $0 ]] && return || exit
				;;
		esac
	done
fi

if [[ -e "$ODP_PATH/scripts/sanity_log" ]]
then
	rm "$ODP_PATH/scripts/sanity_log"
fi

if [[ -e "$ODP_PATH/scripts/sanity_tested_apps" ]]
then
	rm "$ODP_PATH/scripts/sanity_tested_apps"
fi

if [[ -e "$ODP_PATH/scripts/sanity_untested_apps" ]]
then
	rm "$ODP_PATH/scripts/sanity_untested_apps"
fi

if [[ -e "$ODP_PATH/scripts/sanity_test_report" ]]
then
	rm "$ODP_PATH/scripts/sanity_test_report"
fi

#/* Variables represent colors */
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

check_resources
RET=$?
if [[ $RET == 1 ]]
then
	get_resources
fi
main
set +m
