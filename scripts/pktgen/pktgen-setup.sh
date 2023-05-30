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

mlxconfig -d $PORT_PCI_ADDRESS set CQE_COMPRESSION=1

# echo "Setting PCI Max Read Request Size to 1024 (assuming one NIC port i.e. one PCI address)..."
# pci=`ethtool -i $1 | grep 'bus-info:' | sed 's/bus-info: //'`
# setpci -s $pci 68.w=3BCD

# huge pages
echo "Configuring huge pages..."
echo "Please configure huge pages on boot time e.g. 'default_hugepagesz=1G hugepagesz=1G hugepages=64'"
# echo 32 > /sys/kernel/mm/hugepages/hugepages-1048576kB/nr_hugepages

# mkdir -p /mnt/huge
# chmod 777 /mnt/huge
# mount -t hugetlbfs nodev /mnt/huge
