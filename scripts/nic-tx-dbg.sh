#!/bin/bash

if [[ "$1" != "" ]]; then
    NIC=$1
else
    echo "Please provide the network interface you'd like to monitor."
    echo "example: $0 eth0"
    exit 1
fi

values_now=$(ethtool -S $1 | egrep "tx0_xsk_xmit|tx0_xsk_mpwqe|tx0_xsk_inlnw|tx0_xsk_cqes|rx0_xsk_buff_alloc_err" | sort | awk '{print $2}' ORS=' ')
rx0_xsk_buff_alloc_err=$(echo $values_now | awk '{print $1}')
tx0_xsk_cqes=$(echo $values_now | awk '{print $2}')
tx0_xsk_inlnw=$(echo $values_now | awk '{print $3}')
tx0_xsk_mpwqe=$(echo $values_now | awk '{print $4}')
tx0_xsk_xmit=$(echo $values_now | awk '{print $5}')

echo -e "XMIT\t\tMPWQE\t\tINLNW\t\tCQE\t\tBuff Alloc Err"
while sleep 1; do
    values_now=$(ethtool -S $1 | egrep "tx0_xsk_xmit|tx0_xsk_mpwqe|tx0_xsk_inlnw|tx0_xsk_cqes|rx0_xsk_buff_alloc_err" | sort | awk '{print $2}' ORS=' ')
    rx0_xsk_buff_alloc_err_now=$(echo $values_now | awk '{print $1}')
    tx0_xsk_cqes_now=$(echo $values_now | awk '{print $2}')
    tx0_xsk_inlnw_now=$(echo $values_now | awk '{print $3}')
    tx0_xsk_mpwqe_now=$(echo $values_now | awk '{print $4}')
    tx0_xsk_xmit_now=$(echo $values_now | awk '{print $5}')
    
    xmit=$((tx0_xsk_xmit_now - tx0_xsk_xmit))
    if [[ "$xmit" -gt "0" ]]; then
        mpwqe=$((tx0_xsk_mpwqe_now - tx0_xsk_mpwqe))
        inlnw=$((tx0_xsk_inlnw_now - tx0_xsk_inlnw))
        cqes=$((tx0_xsk_cqes_now - tx0_xsk_cqes))
        buff_alloc_err=$((rx0_xsk_buff_alloc_err_now - rx0_xsk_buff_alloc_err))
        echo -e "$xmit\t\t$mpwqe\t\t$inlnw\t\t$cqes\t\t$buff_alloc_err"
    fi

    tx0_xsk_xmit=$tx0_xsk_xmit_now
    tx0_xsk_mpwqe=$tx0_xsk_mpwqe_now
    tx0_xsk_inlnw=$tx0_xsk_inlnw_now
    tx0_xsk_cqes=$tx0_xsk_cqes_now
    rx0_xsk_buff_alloc_err=$rx0_xsk_buff_alloc_err_now
done
