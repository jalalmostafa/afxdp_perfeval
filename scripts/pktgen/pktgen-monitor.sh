#!/bin/bash

if [[ "$1" != "" ]]; then
    NIC=$1
else
    echo "Please provide the network interface you'd like to monitor."
    echo "example: $0 eth0"
    exit 1
fi

p=0
d=0

echo -e "Recv. PPS\t\tDropped PPS\t\tDropped (%)"
while sleep 1; do
    p_now=$(cat /sys/class/net/$NIC/statistics/rx_packets)
    d_now=$(cat /sys/class/net/$NIC/statistics/rx_dropped)

    if [[ "$p" -gt "0" ]]; then
        dropped=$((d_now - d))
        rx=$((p_now - p))
        perc_d=$(echo "scale=5;($dropped/$rx)*100" | bc -l)
        echo -e "$rx\t\t\t$dropped\t\t$perc_d%"
    fi
    p=$p_now
    d=$d_now
done
