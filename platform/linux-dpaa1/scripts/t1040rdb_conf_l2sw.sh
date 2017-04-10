#!/bin/sh
# T1040RDB has the following L2 switch connections:
# Port 8 -- fm0-mac1
# Port 9 -- fm0-mac2
# Port 0,1 - external PHYs
# The configuration effectively connects the Fman ports
# to external PHYs.

# Configure untagged frames for ports 0,1
# to be classified in VLANs 10,11
l2switch-cfg port 0 vlan 10
l2switch-cfg port 1 vlan 11
l2switch-cfg port 8 vlan 10
l2switch-cfg port 9 vlan 11

# Add ports 0,8 and 1,9 in VLANs 10, 11
l2switch-cfg vlan 10 add 8
l2switch-cfg vlan 10 add 0
l2switch-cfg vlan 11 add 1
l2switch-cfg vlan 11 add 9

# Disable MAC learning
l2switch-cfg mac learn off
