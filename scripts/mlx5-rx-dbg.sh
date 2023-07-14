#!/bin/bash

if [[ "$1" != "" ]]; then
    NIC=$1
else
    echo "Please provide the network interface you'd like to monitor."
    echo "example: $0 eth0"
    exit 1
fi

rx_xsk_buff_alloc_err=0
rx_xsk_congst_umr=0
rx_xsk_packets=0
rx_xsk_xdp_drop=0
rx_xsk_xdp_redirect=0
rx_xdp_drop=0
rx_packets_phy=0

while sleep 1; do
    values_now=$(ethtool -S $NIC | grep -w "rx_packets\|rx_packets_phy\|rx_xsk_xdp_drop\|rx_xsk_buff_alloc_err\|rx_xsk_xdp_redirect\|rx_xsk_congst_umr\|rx_xdp_drop" | awk '{print $2}' ORS=' ')
    rx_xsk_packets_now=$(echo $values_now | awk '{print $1}')
    rx_xdp_drop_now=$(echo $values_now | awk '{print $2}')
    rx_xsk_xdp_drop_now=$(echo $values_now | awk '{print $3}')
    rx_xsk_xdp_redirect_now=$(echo $values_now | awk '{print $4}')
    rx_xsk_buff_alloc_err_now=$(echo $values_now | awk '{print $5}')
    rx_xsk_congst_umr_now=$(echo $values_now | awk '{print $6}')
    rx_packets_phy_now=$(echo $values_now | awk '{print $7}')

    rx_pps=$((rx_xsk_packets_now - rx_xsk_packets))
    rx_rdr=$((rx_xsk_xdp_redirect_now - rx_xsk_xdp_redirect))
    if [[ "$rx_rdr" -gt "0" ]]; then
        rx_oob=$((rx_xsk_buff_alloc_err_now - rx_xsk_buff_alloc_err))
        rx_umr=$((rx_xsk_congst_umr_now - rx_xsk_congst_umr))
        rx_drp=$((rx_xsk_xdp_drop_now - rx_xsk_xdp_drop))
        rx_xdp_drp=$((rx_xdp_drop_now - rx_xdp_drop))
        rx_phy=$((rx_packets_phy_now - rx_packets_phy))
        columns="PPS,Phy PPS,Out-of-Buffer,Congst UMR,Drop,Redirects,XDP Drop"
        echo -e "$rx_pps\t\t$rx_phy\t\t$rx_oob\t\t$rx_umr\t\t$rx_drp\t\t$rx_rdr\t\t$rx_xdp_drp\t\t" | column --table --table-columns "$columns" --output-separator "|"
    fi

    rx_xsk_buff_alloc_err=$rx_xsk_buff_alloc_err_now
    rx_xsk_congst_umr=$rx_xsk_congst_umr_now
    rx_xsk_packets=$rx_xsk_packets_now
    rx_xsk_xdp_drop=$rx_xsk_xdp_drop_now
    rx_xsk_xdp_redirect=$rx_xsk_xdp_redirect_now
    rx_xdp_drop=$rx_xdp_drop_now
    rx_packets_phy=$rx_packets_phy_now
done
