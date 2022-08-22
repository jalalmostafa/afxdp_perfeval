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

#### DPDK Configuration
1. Setup huge pages and hugetlbfs
```bash
echo 2048 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages

mkdir -p /mnt/huge
chmod 777 /mnt/huge
mount -t hugetlbfs nodev /mnt/huge
```
2. Ensure Intel VT-d or AMD-V is enabled in the BIOS and PCIe Passthrough is possible in the kernel
```bash
dmesg | grep DMAR # "DMAR: IOMMU enabled" -> VT-d or AMD-V is enabled
```
If not enabled, enable Intel VT-d or AMD-V in the BIOS. For intel CPUs, add `intel_iommu=on` to kernel commandline. for AMD CPUs it should be enabled automatically.

```bash
`vim /etc/default/grub`
# Add `intel_iommu=on` to `GRUB_CMDLINE_LINUX_DEFAULT`
GRUB_CMDLINE_LINUX_DEFAULT="intel_iommu=on"
update-grub
```
Then reboot and check again using `dmesg | grep DMAR`

3. Load vfio kernel modules by adding the following modules to `/etc/modules`:

```bash
vfio
vfio_iommu_type1
vfio_pci
vfio_virqfd
```
Then `update-initramfs -u -k all`.

4. Reboot and check: `dmesg | grep -e DMAR -e IOMMU -e AMD-Vi` should display that `IOMMU`, `Directed I/O` or `Interrupt Remapping` is enabled, depending on hardware and kernel the exact message can vary.

It is also important that the device(s) you want to pass through are in a separate IOMMU group. This can be checked with:

`find /sys/kernel/iommu_groups/ -type l`

5. Everything ok? Bind the device to DPDK drivers if needed
```
# set link down
ip link set dev enp2s0np0 down
python3 dpdk-devbind.py -b vfio-pci 02:00.0
```
### Test Environment

Run `./testenv.sh` with no parameter to get a list of available commands, or
run `./testenv.sh --help` to get the full help listing with all options. The
script can maintain several environments active at the same time, and you
can switch between them using the `--name` option.

If you don't specify a name, the most recently used environment will be
used. If you don't specify a name when setting up a new environment, a
random name will be generated for you.

Examples:

- Setup new environment named "test": `./testenv.sh setup --legacy-ip --name=test`
- Create a shell alias for easy use of script from anywhere: `eval $(./testenv.sh alias)`
- See the currently active environment, and a list of all active environment names (with alias defined as above): `t status`
- Enter the currently active environment: `t enter`
- Execute a command inside the environment: `t exec -- ip a`
- Teardown the environment: `t teardown`
