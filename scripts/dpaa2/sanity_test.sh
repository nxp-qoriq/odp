#/*
# * Copyright (c) 2014 Freescale Semiconductor, Inc. All rights reserved.
# */

# Mount HUGETLB Pages first
cd /mnt
mkdir hugepages
cd -
mount -t hugetlbfs none /mnt/hugepages

echo "#1)    Allow unsafe interrupts"
echo 1 > /sys/module/vfio_iommu_type1/parameters/allow_unsafe_interrupts
echo "#1.1)    dprc container driver override"
echo vfio-fsl-mc > /sys/bus/fsl-mc/devices/dprc.2/driver_override
echo "#1.2)    Bind dprc.2 to VFIO driver"
echo dprc.2 > /sys/bus/fsl-mc/drivers/vfio-fsl-mc/bind
echo "#1.1)    dprc container driver override"
echo vfio-fsl-mc > /sys/bus/fsl-mc/devices/dprc.4/driver_override
echo "#1.2)    Bind dprc.4 to VFIO driver"
echo dprc.4 > /sys/bus/fsl-mc/drivers/vfio-fsl-mc/bind

ls /dev/vfio/


echo
echo
echo " #1)	REFLECTOR -----> y/n "
read res
if [ $res = y ] ; then
######## Reflector ############
	echo
	echo
	echo
	echo
	./reflector -g dprc.4 -lcl
	echo
	echo " ------ Press ENTER To Start Next Test ---------"
	read
fi

######## KNI ############
echo
echo
echo
echo "#2)    KNI  --------> y/n"
read res
if [ $res = y ] ; then
	echo
	echo
	FILE=odpfsl_kni.ko
	if [ -f $FILE ];
	then
		insmod odpfsl_kni.ko
	else
		insmod ../../drv/odpfsl_kni.ko
	fi
	echo
	echo
	./kni_demo -g dprc.4 -lcl &
	echo
	read
	echo " ------ ENTER to config KNI I/F ---------"
	read
	echo
	ifconfig keth-6 6.6.6.10
	echo
	echo
	echo " ------ ENTER  to kill KNI ---------"
	echo
	read
	echo
	pid=`ps | pgrep kni_demo`
	kill -2 $pid
	echo " ------ Press ENTER To Start Next Test ---------"
	read
fi

######## Multi VQ ############
echo
echo
echo
echo "#3)    Multi VQ  ------> y/n"
read res
if [ $res = y ] ; then
	echo " Verify following "
	echo "Create arp for 6.6.6.10 & 6.6.6.11"
	echo
	echo
	./test_mvq -g dprc.4 -lcl
	echo
	echo " ------ Press ENTER To Start Next Test ---------"
	echo
	read
fi

######## CONC ############
echo
echo
echo
echo "#4)    Concentrator  ------> y/n"
read res
if [ $res = y ] ; then
	echo " Verify following "
	echo
	echo
	./test_conc -g dprc.4 -n 4 -lcl
	echo
	echo " ------ Press ENTER To Start Next Test ---------"
	echo
	read
fi

######## Simple Crypto ############
echo
echo
echo "#5)	Simple Crypto -----> y/n "
read res
if [ $res = y ] ; then
	echo
	echo
	echo
	echo
	./simple_crypto -g dprc.4 -l 6 -c 4 -s 128 -o 1
	echo
	echo " ------ Press ENTER To Start Next Test ---------"
	read
fi

######## TX Conf ERR ############
echo
echo
echo
echo "#6)    TX Conf-Err  ----> y/n"
read res
if [ $res = y ] ; then
	echo
	echo "Mode -1 Transmit a invalid frame with invalid length"
	echo
	echo
	./tx_conf_err -g dprc.4 -lcl -m 1
	echo
	echo "Mode -2 Transmit a invalid frame with non DMA’ble memory"
	echo
	echo
	./tx_conf_err -g dprc.4 -lcl -m 2
	echo
	echo "Mode -3 Transmit a valid frame & validates it's confirmation"
	echo
	echo
	./tx_conf_err -g dprc.4 -lcl -m 3
	echo
	echo
	echo " ------ Press ENTER To Start Next Test ---------"
	read
fi

######## CMDIF CLIENT############
echo
echo
echo
echo
echo "#7)    CMDIF Client  --- > y/n"
read res
if [ $res = y ] ; then
	echo " Verify following "
	echo "PASSED open commands, PASSED synchronous send commands"
	echo "PASSED asynchronous send/receive commands,PASSED close commands"
	echo
	echo
	./cmdif_client_demo -g dprc.2 -l 6 -lcl
	echo
	echo
	echo " ------ Press ENTER To Start Next Test ---------"
	read
fi

######## CMDIF SERVER ############
echo
echo
echo
echo "#8)    CMDIF Server  ----> y/n"
read res
if [ $res = y ] ; then
	echo " Verify following "
	echo "PASSED cmdif session open"
	echo "PASSED Async commands"
	echo
	echo
	./cmdif_server_demo -g dprc.2 -l 6 -lcl
	echo
	echo
	echo " ------ Press ENTER To Start Next Test ---------"
	echo
	read
fi

######## L3 FWD ############
echo
echo
echo
echo "#9)    L3_FWD  ----> y/n"
read res
if [ $res = y ] ; then
	echo "Running l3fwd app in background"
	echo
	echo
	./l3fwd -g dprc.4 &
	echo
	echo
	echo
	read
	echo " ------ ENTER to configure L3fwd rules ---------"
	read
	pid=`ps | pgrep l3fwd`
	echo
	#!/bin/sh
	# For Listing down all the network interfaces (NI)
	./l3fwd_config -P $pid -E -a true

	# For Assigning IP address to NI
	./l3fwd_config -P $pid -F -a 192.168.2.1 -i 1
	./l3fwd_config -P $pid -F -a 192.168.3.1 -i 2

	# For Adding Static ARP entries
	./l3fwd_config -P $pid -G -s 192.168.2.2 -m 02:00:c0:a8:3c:02 -r true
	./l3fwd_config -P $pid -G -s 192.168.3.2 -m 02:00:c0:a8:a0:02 -r true

	# For Adding Route Entries
	./l3fwd_config -P $pid -B -s 192.168.2.2 -d 192.168.3.2 -g 192.168.3.2
	./l3fwd_config -P $pid -B -s 192.168.3.2 -d 192.168.2.2 -g 192.168.2.2

	echo
	echo
	echo " ------ On HOST run following Name Space settings---------"
	echo
	echo " ------> Create following Tuntap I/Fs"
	echo tuntap_if_configure.sh create dpaa2_l3fwd_1 02:00:c0:a8:3c:02 192.168.2.2
	echo tuntap_if_configure.sh create dpaa2_l3fwd_2 02:00:c0:a8:a0:02 192.168.3.2
	echo
	echo
	echo " ------> Attach Tuntap I/Fs"
	echo start_tio_bridge.sh -m w0_m6 -n dpaa2_l3fwd_1
	echo start_tio_bridge.sh -m w0_m7 -n dpaa2_l3fwd_2
	echo
	echo
	echo " ------> Run Below CMDs"
	echo
	echo sudo ip netns add ns1
	echo sudo ip link set dpaa2_l3fwd_2 netns ns1
	echo sudo ip netns exec ns1 ifconfig dpaa2_l3fwd_2 192.168.3.2
	echo sudo ip netns exec ns1 route add -net 192.168.2.0/24 gw 192.168.3.1
	echo sudo ip netns exec ns1 arp -s 192.168.3.1 00:00:00:00:00:07
	echo
	echo sudo arp -s 192.168.2.1 00:00:00:00:00:06
	echo sudo route add -net 192.168.3.0/24 gw 192.168.2.1
	echo
	echo ping 192.168.3.2
	echo
	echo " ------ ENTER  to kill L3FWD app ---------"
	echo
	read
	echo "Run following commands on Host to restore interface & Namespace"
	echo
	echo
	echo sudo ip netns exec ns1 ip link set dpaa2_l3fwd_2 netns 1
	echo sudo ip netns delete ns1
	echo
	echo
	kill -2 $pid
	echo " ------ Press ENTER To Start Next Test ---------"
	read
fi

######## Timer ############
echo
echo
echo
echo "#10)    Timer  ---> y/n"
read res
if [ $res = y ] ; then
	echo "Static Timer -------"
	echo
	./timer_demo -s 2000
	echo
	echo
	echo
	read
	echo "Preodic Timer  ---------"
	echo
	./timer_demo -p 2000
	echo
	echo
fi
