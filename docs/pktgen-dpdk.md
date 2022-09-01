# Pktgen-dpdk

## Build

## DPDK Configuration


1. GRUB configuration:
    ```bash
    isolcpus=0-39 nohz_full=0-39 rcu_nocbs=0-39 intel_iommu=on iommu=pt
    default_hugepagesz=1G hugepagesz=1G hugepages=80 intel_idle.max_cstate=0
    processor.max_cstate=0 intel_pstate=disable rcu_nocb_poll audit=0
    ```


2. Flow Control OFF: `ethtool -A $netdev rx off tx off`

3. Memory optimizations: 
    ```bash
    sysctl -w vm.zone_reclaim_mode=0
    sysctl -w vm.swappiness=0
    ```

4. Move all IRQs to far NUMA node: `IRQBALANCE_BANNED_CPUS=$LOCAL_NUMA_CPUMAP irqbalance --oneshot`

5. Disable irqbalance: `systemctl stop irqbalance`

6. Change PCI MaxReadReq to 1024B for each port of each NIC:
    ```bash
    setpci -s $PORT_PCI_ADDRESS 68.w # it will return 4 digits ABCD
    setpci -s $PORT_PCI_ADDRESS 68.w=3BCD
    ```

7. Set CQE COMPRESSION to AGGRESSIVE: `mlxconfig -d $PORT_PCI_ADDRESS set CQE_COMPRESSION=1`

8. Disable Linux realtime throttling: `echo -1 > /proc/sys/kernel/sched_rt_runtime_us`

9. Setup huge pages and hugetlbfs
    ```bash
    mkdir -p /mnt/huge
    chmod 777 /mnt/huge
    mount -t hugetlbfs nodev /mnt/huge
    ```

11. Load vfio kernel modules by adding the following modules to `/etc/modules`:

    ```bash
    vfio
    vfio_iommu_type1
    vfio_pci
    vfio_virqfd
    ```
    Then `update-initramfs -u -k all`.

12. Reboot and check: `dmesg | grep -e DMAR -e IOMMU -e AMD-Vi` should display that `IOMMU`, `Directed I/O` or `Interrupt Remapping` is enabled, depending on hardware and kernel the exact message can vary.

    It is also important that the device(s) you want to pass through are in a separate IOMMU group. This can be checked with: `find /sys/kernel/iommu_groups/ -type l`

13. Everything ok? Bind the device to DPDK drivers if needed. Mellanox PMD does not device binding.
    ```
    # set link down
    ip link set dev enp2s0np0 down
    python3 dpdk-devbind.py -b vfio-pci 02:00.0
    ```

## Run
