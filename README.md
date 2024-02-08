# AF_XDP Performance Evaluation

[![DOI](https://zenodo.org/badge/448600339.svg)](https://zenodo.org/badge/latestdoi/448600339)

## Citation

Please cite our work:
> J. Mostafa, S. Chilingaryan and A. Kopmann, "Are Kernel Drivers Ready For Accelerated Packet Processing Using AF_XDP?," 2023 IEEE Conference on Network Function Virtualization and Software Defined Networks (NFV-SDN), Dresden, Germany, 2023, pp. 117-122, doi: 10.1109/NFV-SDN59219.2023.10329590. keywords: {Measurement;Sockets;Linux;Documentation;Throughput;Network function virtualization;Behavioral sciences;AF_XDP;zero-copy networking;software data planes;DPDK;kernel drivers;user-space drivers},

### Bibtex
```bibtex
@INPROCEEDINGS{10329590,
  author={Mostafa, Jalal and Chilingaryan, Suren and Kopmann, Andreas},
  booktitle={2023 IEEE Conference on Network Function Virtualization and Software Defined Networks (NFV-SDN)}, 
  title={Are Kernel Drivers Ready For Accelerated Packet Processing Using AF_XDP?}, 
  year={2023},
  volume={},
  number={},
  pages={117-122},
  keywords={Measurement;Sockets;Linux;Documentation;Throughput;Network function virtualization;Behavioral sciences;AF_XDP;zero-copy networking;software data planes;DPDK;kernel drivers;user-space drivers},
  doi={10.1109/NFV-SDN59219.2023.10329590}}
```

## Build

For Ubuntu
```bash
apt install clang llvm libelf-dev libpcap-dev gcc-multilib build-essential linux-tools-common linux-tools-generic linux-headers-$(uname -r) m4 libnuma-dev
```

For RHEL/CentOS
```bash
sudo yum --enablerepo=powertools install llvm clang elfutils-libelf-devel libpcap-devel m4 numactl-devel
```

```bash
git clone --recursive https://github.com/jalalmostafa/afxdp_perfeval.git
cd afxdp_perfeval/src
make
```

## Experimentation

### t-rex
T-Rex is used to measure latency. Docs how to setup, build, and run t-rex are available in [docs/trex](docs/trex.md)

### pktgen-dpdk
Pktgen-dpdk is used to generate packets of different packet sizes. A guide how to setup and run with configuration is available in [docs/pktgen-dpdk](docs/pktgen-dpdk.md).

### Using veth
We provide scripts to run our benchmarks using virtual interfaces on the same machine (just for testing purposes). Details in [docs/veth](docs/veth.md)

### `mlx5` MPWQE Inlining Algorithm
Disable `mlx5` MPWQE Inlining Algorithm in the source code using the patch available in `mlx5-disable-inlining.patch`.
Apply the patch using: `patch -p0 < mlx5-disable-inlining.patch` in the kernel source code, compile and install the modified kernel then restart the server using this kernel.

## Running

```bash
Usage: ./dqdk -i <interface_name> -q <hardware_queue_id>
Arguments:
    -d <duration>                Set the run duration in seconds. Default: 3 secs
    -i <interface>               Set NIC to work on
    -q <qid[-qid]>               Set range of hardware queues to work on e.g. -q 1 or -q 1-3.
                                 Specifying multiple queues will launch a thread for each queue except if -p poll
    -m <native|offload|generic>  Set XDP mode to 'native', 'offload', or 'generic'. Default: native
    -c                           Enforce XDP Copy mode, default is zero-copy mode
    -v                           Verbose
    -b <size>                    Set batch size. Default: 64
    -w                           Use XDP need wakeup flag
    -p <poll|rtc>                Enforce poll or run-to-completion mode. Default: rtc
    -s <nb_xsks>                 Set number of sockets working on shared umem
    -t <tx-packet-size>          Set txonly packet size
    -u                           Use unaligned memory for UMEM
    -A <irq1,irq2,...>           Set affinity mapping between application threads and drivers queues
                                 e.g. q1 to irq1, q2 to irq2,...
    -I <irq_string>              `grep` regex to read and count interrupts of interface from /proc/interrupts
    -M <rxdrop|txonly|l2fwd>     Set Microbenchmark. Default: rxdrop
    -B                           Enable NAPI busy-poll
    -D <dmac>                    Set destination MAC address for txonly
    -H                           Considering Hyper-threading is enabled, this flag will assign affinity
                                 of softirq and the app to two logical cores of the same physical core.
    -G                           Activate Huge Pages for UMEM allocation
    -S                           Run IRQ and App on same core
```

## Driver Support (as of Linux v6.5-rc2)

| Vendor                   | Driver           | Mode           | Need Wake Up      |
| ------------------------ | ---------------- | -------------- | ----------------- |
| Intel                    | i40e             | ZC/C           | Y                 |
|                          | ice              | ZC/C           | Y                 |
|                          | igb              | C              | N                 |
|                          | igc              | ZC/C           | Y                 |
|                          | ixgbe            | ZC/C           | Y                 |
|                          | ixgbevf          | C              | N                 |
| NVIDIA/Mellanox          | mlx5             | ZC/C           | Y                 |
|                          | mlx4             | C              | N                 |
| Broadcom                 | bnxt             | C              | N                 |
| Netronome/Corigine       | nfp              | ZC/C           | N                 |
| Marvell                  | mvneta           | C              | N                 |
|                          | mvpp2            | C              | N                 |
|                          | octeontx2        | C              | N                 |
| Qlogic (now Marvell)     | qede             | C              | N                 |
| Cavium (now Marvell)     | thunder          | C              | N                 |
| Aquantia (now Marvell)   | atlantic         | C              | N                 |
| MediaTek                 | mtk              | C              | N                 |
| MicroChip                | lan966x          | C              | N                 |
| SolarFlare (now Xilinx)  | efx              | C              | N                 |
|                          | siena-efx        | C              | N                 |
| SocioNext                | netsec           | C              | N                 |
| STMicroelectronics       | stmmac           | ZC/C           | Y                 |
| Texas Instruments        | cpsw             | C              | N                 |
| Freescale (now NXP)      | dpaa             | C              | N                 |
|                          | dpaa2            | ZC/C           | N                 |
|                          | enetc            | C              | N                 |
|                          | fec              | C              | N                 |
| Engleder                 | tsnep            | ZC/C           | Y                 |
| Fungible (now Microsoft) | funeth           | C              | N                 |
| Microsoft                | mana             | C              | N                 |
| Microsoft Hyper-V        | netvsc           | C              | N                 |
| Amazon                   | ena              | C              | N                 |
| Google                   | gve              | ZC/C           | only on TX path   |
| Xen                      | netfront         | C              | N                 |
| VirtIO                   | virtio\_net      | C              | N                 |
| Linux                    | tun              | C              | N                 |
|                          | veth             | C              | N                 |
|                          | bonding          | C              | N                 |
|                          | netdevsim        | C              | N                 |
