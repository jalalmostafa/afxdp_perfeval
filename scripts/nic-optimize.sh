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
ip link set dev $NIC mtu 3498

max_hw_rxq=`ethtool -g $NIC | grep -m 1 RX: | awk '{print $2}'`
max_hw_txq=`ethtool -g $NIC | grep -m 1 TX: | awk '{print $2}'`

echo "ethtool-based Optimizations"
ethtool -A $NIC tx off rx off
ethtool -G $NIC tx $max_hw_txq rx $max_hw_rxq
ethtool -L $NIC combined $queues
ethtool -C $NIC adaptive-rx off adaptive-tx off rx-usecs 0
ethtool -K $NIC gro off rx-fcs off sg off tx-ipxip4-segmentation off rx-checksumming off tx-checksumming off \
tx-udp-segmentation off gso off rx-gro-list off tso off tx-ipxip6-segmentation off \
tx-udp_tnl-csum-segmentation off hw-tc-offload off rx-vlan-stag-filter off \
rx-udp-gro-forwarding off tx off tx-nocache-copy off tx-udp_tnl-segmentation off \
lro off rx-udp_tunnel-port-offload off tx-checksum-ip-generic off \
tx-scatter-gather off tx-vlan-stag-hw-insert off ntuple on rx-vlan-filter off \
tx-gre-csum-segmentation off tx-tcp-mangleid-segmentation off txvlan off rx off \
rxhash off tx-gre-segmentation off tx-tcp-segmentation off rx-all off rxvlan off \
tx-gso-partial off tx-tcp6-segmentation off rx-checksumming off tx-checksumming off
#ethtool --set-priv-flags $1 rx_cqe_moder off tx_cqe_moder off rx_cqe_compress off \
#                            rx_striding_rq off rx_no_csum_complete off xdp_tx_mpwqe off \
#                            skb_tx_mpwqe off tx_port_ts off

#echo "Setting PCI Max Read Request Size to 1024 (assuming one NIC port i.e. one PCI address)..."
# commented because was causing some problem, I forgot which one, they are a lot! :(
#pci=`ethtool -i $1 | grep 'bus-info:' | sed 's/bus-info: //'`
#setpci -s $pci 68.w=3BCD

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
