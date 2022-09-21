#! /bin/bash

if [[ "$1" != "" ]]; then
    NIC=$1
else
    echo "Please provide the network interface you'd like to monitor."
    echo "example: $0 eth0"
    exit 1
fi

queues=1
if [[ "$2" != "" ]]; then
    queues=$2
fi

max_hw_rxq=`ethtool -g $1 | grep -m 1 RX: | awk '{print $2}'`
max_hw_txq=`ethtool -g $1 | grep -m 1 TX: | awk '{print $2}'`

echo "ethtool-based Optimizations"
ethtool -A $1 tx off rx off
ethtool -G $1 tx $max_hw_txq rx $max_hw_rxq
ethtool -L $1 combined $queues
ethtool -C $1 adaptive-rx off adaptive-tx off rx-usecs 0
ethtool -K $1 gro off rx-fcs off sg off tx-ipxip4-segmentation off rx-checksumming off tx-checksumming off \
tx-udp-segmentation off gso off rx-gro-list off tso off tx-ipxip6-segmentation off \
tx-udp_tnl-csum-segmentation off hw-tc-offload off rx-vlan-stag-filter off \
rx-udp-gro-forwarding off tx off tx-nocache-copy off tx-udp_tnl-segmentation off \
lro off rx-udp_tunnel-port-offload off tx-checksum-ip-generic off \
tx-scatter-gather off tx-vlan-stag-hw-insert off ntuple off rx-vlan-filter off \
tx-gre-csum-segmentation off tx-tcp-mangleid-segmentation off txvlan off rx off \
rxhash off tx-gre-segmentation off tx-tcp-segmentation off rx-all off rxvlan off \
tx-gso-partial off tx-tcp6-segmentation off rx-checksumming off tx-checksumming off
ethtool --set-priv-flags $1 rx_cqe_moder on rx_cqe_compress on tx_cqe_moder on tx_cqe_compress on

echo "Setting PCI Max Read Request Size to 1024 (assuming one NIC port i.e. one PCI address)..."
pci=`ethtool -i $1 | grep 'bus-info:' | sed 's/bus-info: //'`
setpci -s $pci 68.w=3BCD

echo "Optimizing Virtual Memory Usage..."
sysctl -w vm.zone_reclaim_mode=0
sysctl -w vm.swappiness=0

echo "Disabling irqbalance..."
systemctl disable irqbalance
systemctl stop irqbalance

# IRQ affinity
irqbalance stop
if [[ queues -eq 1 ]]; then
    set_irq_affinity_cpulist.sh 3 $1
else
    lcpu=$(($queues-1))
    affinity="0-$lcpu"
    set_irq_affinity_cpulist.sh $affinity $1
fi

