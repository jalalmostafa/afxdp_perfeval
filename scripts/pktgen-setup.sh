#! /bin/bash
set -e

if [[ $EUID -ne 0 ]]; then
    echo "Run as root. Exiting..."
    exit 1
fi

if [[ -z $1 ]]; then
    echo "$0 <nic>"
    echo "Network interface name is needed!"
    exit 1
fi

# low latency setup
echo "Disabling Real-time Throttling..."
echo -1 > /proc/sys/kernel/sched_rt_runtime_us

# NIC setup
echo "Disabling NIC Pausing..."
ethtool -A $1 rx off tx off

echo "Optimizing Virtual Memory Usage..."
sysctl -w vm.zone_reclaim_mode=0
sysctl -w vm.swappiness=0

echo "Disabling irqbalance..."
systemctl disable irqbalance
systemctl stop irqbalance

echo "Setting PCI Max Read Request Size to 1024 (assuming one NIC port i.e. one PCI address)..."
pci=`ethtool -i $1 | grep 'bus-info:' | sed 's/bus-info: //'`
setpci -s $pci 68.w=3BCD

# huge pages
echo "Configuring huge pages..." 
echo 32 > /sys/kernel/mm/hugepages/hugepages-1048576kB/nr_hugepages

mkdir -p /mnt/huge
chmod 777 /mnt/huge
mount -t hugetlbfs nodev /mnt/huge
