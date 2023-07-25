#!/bin/bash

if [[ "$1" != "" ]]; then
    NIC=$1
    DURATION=$((10 + $2))
    CORES=$3
else
    echo "Please provide the network interface you'd like to monitor."
    echo "example: $0 eth0 <seconds> <other-dqdk-arguments>"
    exit 1
fi

pci=`ethtool -i $NIC | grep 'bus-info:' | sed 's/bus-info: //'`

pcm-pcie -B -i=$DURATION -csv=./pcie.csv > ./pcm-pcie.log 2>&1 &

timeout $DURATION dpdk-testpmd -l 16-31 -n 8 --proc-type auto --log-level 7 --file-prefix pg -a "$pci,txqs_min_inline=100" --socket-mem=0,32768 -- --port-numa-config=0,1 --rxd=4096 --txd=4096 --burst=64 --mbcache=512 --forward-mode=macswap -a --nb-cores=$CORES --rxq=$CORES --txq=$CORES
