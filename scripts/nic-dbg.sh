#!/bin/bash

if [[ "$1" != "" ]]; then
    NIC=$1
else
    echo "Please provide the network interface you'd like to monitor."
    echo "example: $0 eth0"
    exit 1
fi

rx_out_of_buffer=0
rx_packets=0
rx_packets_phy=0
rx_steer_missed_packets=0

echo -e "Phy. PPS\t\tPPS\t\tOut-of-Buffer\t\tSteer Missed Packets"
while sleep 1; do
    values_now=$(sudo ethtool -S enp2s0np0 | grep "rx_packets\|rx_packets_phy\|rx_out_of_buffer\|rx_steer_missed_packets" | sort | awk '{print $2}' ORS=' ')
    rx_out_of_buffer_now=$(echo $values_now | awk '{print $1}')
    rx_packets_now=$(echo $values_now | awk '{print $2}')
    rx_packets_phy_now=$(echo $values_now | awk '{print $3}')
    rx_steer_missed_packets_now=$(echo $values_now | awk '{print $4}')
    
    if [[ "$rx_packets_phy" -gt "0" ]]; then
        rx_oob=$((rx_out_of_buffer_now - rx_out_of_buffer))
        rx_pps=$((rx_packets_now - rx_packets))
        rx_phypps=$((rx_packets_phy_now - rx_packets_phy))
        rx_smp=$((rx_steer_missed_packets_now - rx_steer_missed_packets))
        echo -e "$rx_phypps\t\t$rx_pps\t\t$rx_oob\t\t$rx_smp"
    fi

    rx_out_of_buffer=$rx_out_of_buffer_now
    rx_packets=$rx_packets_now
    rx_packets_phy=$rx_packets_phy_now
    rx_steer_missed_packets=$rx_steer_missed_packets_now
done
