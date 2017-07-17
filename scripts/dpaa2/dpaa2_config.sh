#/*
# * Copyright (c) 2015-2016 Freescale Semiconductor, Inc. All rights reserved.
# *
# *
# */

#/* Configuration file to export the various required DPAA2/ODP environment variables.
# * Please uncomment the required commands before the execution of this script.
# * Script must be executed at console with prefix source. e.g:
# * source ./dpaa2_config.sh */

######################### DYNAMIC_DPL ######################

#/* DPNI related parameters*/
#/* Supported boards and options*/

#/* Enable/disable Ordered Point Restoration*/
export OPR_ENABLE=1
#/* PEB or DDR*/
export PFDR_IN_DDR_ENABLE=0

#/* Number of Queues*/
export MAX_QUEUES=8
#/* Number of traffic classes*/
export MAX_TCS=1
#/* Number of flow steering entries*/
export FS_ENTRIES=16


#/* Script creating DPNI_OPTIONS based on exported variables*/
if [ -e /sys/firmware/devicetree/base/compatible ]
then
	board_type=`grep -ao '1088\|2088\|2080\|2085\|2160' /sys/firmware/devicetree/base/compatible | head -1`
fi

unset DPNI_OPTIONS
if [[ $OPR_ENABLE == "1" ]]
then
	DPNI_OPTIONS="DPNI_OPT_HAS_OPR"
fi
if [[ $PFDR_IN_DDR_ENABLE == "0" ]]
then
	DPNI_OPTIONS="$DPNI_OPTIONS,0x80000000"
fi
if [[ $board_type == "1088" ]]
then
	export DPNI_OPTIONS="$DPNI_OPTIONS"
elif [[ $board_type == "2080" || $board_type == "2085" || $board_type == "2088" ]]
then
	export DPNI_OPTIONS="$DPNI_OPTIONS,DPNI_OPT_HAS_KEY_MASKING"
else
	echo "Invalid board type $board_type"
	exit
fi

#/* DPCONC related parameters*/
#/* DPCONC object counts*/
export DPCON_COUNT=11
#/* Number of priorities*/
export DPCON_PRIORITIES=2

#/* DPBP related parameters*/
#/* DPBP object counts*/
export DPBP_COUNT=10

#/* DPseci related parameters*/
#/* DPseci object counts*/
export DPSECI_COUNT=1
#/* Number of rx/tx queues*/
export DPSECI_QUEUES=8
#/* Number of priorities*/
export DPSECI_PRIORITIES="2,2,2,2,2,2,2,2"

#/* DPIO related parameters*/
#/* DPIO object counts*/
export DPIO_COUNT=22
#/* Number of priorities*/
export DPIO_PRIORITIES=2

#/* DPIO related parameters*/
#/* DPCI object counts*/
export DPCI_COUNT=20


################## APPLICATION RELATED VARIABLES ################

#/* To enable the promiscous mode*/
# export ENABLE_PROMISC=1

#/ *In case of running ODP on the Virtual Machine the Stashing
# * Destination gets set in the H/W w.r.t. the Virtual CPU ID's.
# * As a W.A. environment variable HOST_START_CPU tells which the
# * offset of the host start core of the Virtual Machine threads.
# */
#export HOST_START_CPU=<cpu_id>

#/* To enable scheduler PULL mode, default is scheduler PUSH mode*/
#export ODP_SCH_PULL_MODE=1

#To specify memory requirement for application in MB.
#export APPL_MEM_SIZE=32


########################### IPSEC ###############################

#/* To enable use of poll queues instead of scheduled*/
#export ODP_IPSEC_USE_POLL_QUEUES=1

#/* To enable use of multiple dequeue for queue draining during
# * stream verification instead of single dequeue */
#export ODP_IPSEC_STREAM_VERIFY_MDEQ=1


########################## INTERRUPTS ###########################

#/* To disable the interrupts in scheduler PUSH mode. Interrupts are
# * enable by default*/
#export ODP_SCH_PUSH_INTR=0

#/* To set the DQRR interrupts threshold value. Valid only
# * if interrupts are enabled. Value is depends upon dqrr ring size.
# * e.g It can be in range 0-7 for 2088 board*/
#export ODP_INTR_THRESHOLD=3

#/* To set the interrupts timeout value. Valid only if
# * interrupts are enabled. Max value can be 0xFFF*/
#export ODP_INTR_TIMEOUT=FF


######################## DEBUG FRAMEWORK ########################

#/* To enable the debug thread*/
#export PLAT_DEBUG_THREAD=1

#/* Socket port number for debug thread*/
#export PLAT_DEBUG_PORT=10000


############################# CUNIT #############################

#/* while testing real-world interfaces additional time may be
# * needed for external network to enable link to pktio
# * interface that just become up. (A test case in pktio_main)*/
#export ODP_WAIT_FOR_NETWORK=1

#/* Interfaces names for pktio_main test cases, otherwise loopback
# * device by default */
#export ODP_PKTIO_IF0=<interface name>
#export ODP_PKTIO_IF1=<interface name>
