# AF_XDP Performance Evaluation

## Build

For Ubuntu
```bash
apt install clang llvm libelf-dev libpcap-dev gcc-multilib build-essential linux-tools-common linux-tools-generic linux-headers-$(uname -r) m4 libnuma-dev libdpdk-dev
```

For RHEL/CentOS
```bash
sudo yum --enablerepo=powertools install llvm clang elfutils-libelf-devel libpcap-devel m4 numactl-devel dpdk-devel
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

## TRISTAN Results

| Packet Size | RSS UDP Ports | 1 Frame every | Queues | Wake up Flag | Huge Pages | Batch Size | Interrupts & Cores | Zero loss | Histo | MPPS | Payload Throughput | 
| ----------- | ------ | --------- | ------------- | ----------- | ------ | --------- | ------------- | ----------- | ------ | ---- | ---- |
| 3392 | 2 | 295nsec | 2 | Yes | Yes | 2048 | 2 Cores / Queue (ints and app) | Yes | No | 3.45 | 93.6% |
