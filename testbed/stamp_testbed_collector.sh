#!/bin/bash

# this script needs to be executed from the eclat-daemon folder
# by calling:
# testbed/time_testbed.sh

#                     +------------------+      +------------------+
#                     |        TG        |      |       SUT        |
#                     |                  |      |                  |
#                     |         enp6s0f0 +------+ enp6s0f0 <--- HIKe VM XDP loader
#                     |                  |      |                  |
#                     |                  |      |                  |
#                     |         enp6s0f1 +------+ enp6s0f1         |
#                     |                  |      |         + cl0  <-|- towards the collector
#                     +------------------+      +---------|--------+
#                                                         |
#                                               +---------|------+
#                                               |         + veth0|
#                                               |                |
#                                               |    COLLECTOR   |
#                                               +----------------+

ECLAT_SCRIPT=components/stamp/eclat_scripts/stamp_collector.eclat

DEBUG_COMMAND="scripts/enter-namespace-debug-no-vm.sh"
DEBUG_EXEC=YES

MAPS_COMMAND="scripts/enter-namespace-watchmap.sh"
MAPS_EXEC=YES

CLT_COMMAND="tcpdump -i veth0"
CLT_EXEC=NO

TG1_COMMAND="scripts/enter-namespace-xdp-raw-pass-tg.sh"
TG1_EXEC=YES

TG2_COMMAND="tcpreplay -i enp6s0f0 components/stamp/pcaps/stamp-srh-reflector.pcap"
TG2_EXEC=NO

MAIN_COMMAND="components/stamp/scripts/enter-namespace-stamp-maps-collector.sh"
MAIN_EXEC=YES

SUT_COMMAND="tcpdump -ni any -w develop/trace.pcap"
SUT_EXEC=NO

source testbed/common_testbed.sh
