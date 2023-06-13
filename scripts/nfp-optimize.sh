#! /bin/bash
set -e

if [ "$1" = "" ]; then
    echo "Please provide the network interface you'd like to monitor."
    echo "example: $0 eth0"
    exit 1
fi

NIC=$1
queues=1
if [[ "$2" != "" ]]; then
    queues=$2
fi

echo "Setting MTU..."
# ip link set dev $NIC mtu 3498

# max_hw_rxq=`ethtool -g $NIC | grep -m 1 RX: | awk '{print $2}'`
# max_hw_txq=`ethtool -g $NIC | grep -m 1 TX: | awk '{print $2}'`

echo "ethtool-based Optimizations"
# ethtool -A $NIC tx off rx off
# ethtool -G $NIC tx $max_hw_txq rx $max_hw_rxq
ethtool -L $NIC combined $queues tx 0 rx 0
ethtool -C $NIC adaptive-rx off adaptive-tx off rx-usecs 0
ethtool -K $NIC rx-checksumming off tx-checksumming off scatter-gather off \
tcp-segmentation-offload off tx-tcp-segmentation off \
tx-tcp-mangleid-segmentation off tx-tcp6-segmentation off \
generic-segmentation-offload off generic-receive-offload off \
receive-hashing on highdma on tx-nocache-copy off hw-tc-offload off \
rx-gro-list off rx-udp-gro-forwarding off

#ethtool --set-priv-flags $1 rx_cqe_moder off tx_cqe_moder off rx_cqe_compress off \
#                            rx_striding_rq off rx_no_csum_complete off xdp_tx_mpwqe off \
#                            skb_tx_mpwqe off tx_port_ts off

echo "Optimizing Virtual Memory Usage..."
sysctl -w vm.zone_reclaim_mode=0
sysctl -w vm.swappiness=0


# IRQ affinity
numa_nodes=`cat /sys/devices/system/node/online`
if [ "0" = "$numa_nodes" ]; then
    echo "Disabling irqbalance..."
    systemctl disable irqbalance
    systemctl stop irqbalance
    echo "Setting IRQ Affinity..."
    echo "No NUMA nodes were detected"
    irqbalance stop
    if [[ queues -eq 1 ]]; then
        set_irq_affinity_cpulist.sh 3 $NIC
    else
        lcpu=$(($queues-1))
        affinity="0-$lcpu"
        set_irq_affinity_cpulist.sh $affinity $NIC
    fi
else
    echo "NUMA nodes were detected: $numa_nodes"
    mlx5_numa_node=`cat /sys/class/net/$NIC/device/numa_node`
    echo "NIC is working on NUMA node $mlx5_numa_node"

    echo "Disabling irqbalance..."
    LOCAL_NUMA_CPUMAP=`cat /sys/devices/system/node/node$mlx5_numa_node/cpumap`
    IRQBALANCE_BANNED_CPUS=$LOCAL_NUMA_CPUMAP irqbalance --oneshot
    systemctl stop irqbalance
    systemctl disable irqbalance

    echo "Setting IRQ Affinity..."
    cpulist=`cat /sys/devices/system/node/node$mlx5_numa_node/cpulist`
    echo "Affinity of $NIC is set to CPUs $cpulist"
    set_irq_affinity_cpulist.sh $cpulist $NIC
    # echo "Run 'set_irq_affinity_cpulist.sh <numa-node-cpu-ranges> $NIC' with respective CPU list of NUMA Node $mlx5_numa_node"
    # echo "Run 'lscpu | grep -i numa' to get CPU lists"
fi
