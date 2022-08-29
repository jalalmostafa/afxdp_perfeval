# AF_XDP Performance Evaluation

## Build

For Ubuntu
```bash
apt install clang llvm libelf-dev libpcap-dev gcc-multilib build-essential linux-tools-common linux-tools-generic linux-headers-$(uname -r)
make
```

For RHEL/CentOS
```bash
sudo yum --enablerepo=powertools install llvm clang elfutils-libelf-devel libpcap-devel
```

```bash
git clone --recursive https://github.com/jalalmostafa/afxdp_perfeval.git
cd afxdp_perfeval/src
make
```

## Experimentation
### pktgen-dpdk
Pktgen-dpdk is used to generate packets of different packet sizes. A guide how to setup and run with configuration is available in [docs/pktgen-dpdk](docs/pktgen-dpdk.md).

### Using veth
We provide scripts to run our benchmarks using virtual interfaces on the same machine (just for testing purposes). Details in [docs/veth](docs/veth.md)

## Running
