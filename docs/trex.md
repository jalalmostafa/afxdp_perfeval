# T-REX

## Installation

```bash
wget https://trex-tgn.cisco.com/trex/release/v3.03.tar.gz
tar xvf v3.03.tar.gz
cd v3.03
```

## Setup

### Create the File `/etc/trex_cfg.yaml`

```yaml
- version: 2
  interfaces: ['b1:00.0', 'dummy']
  port_info:
      - ip: 192.168.20.1
        default_gw: 192.168.20.2
      - ip: 2.2.2.2
        default_gw: 1.1.1.1
  platform :
        master_thread_id  : 16
        latency_thread_id : 17
        dual_if   :
             - socket   : 1
               threads  : [18, 19, 20,21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31]
```

### DPDK Bind

Bind to DPDK if necessary, not necessary for `mlx5` but it requires special dpdk setup

## Run

1. Run the t-rex daemon: `sudo ./t-rex-64 -i -c 14`
2. Run the console: `sudo ./trex-console`
3. In trex-console, run ARP service: `service`, then `arp`, finally `service --off`
4. In the trex-console, latency test using:
    1. Run test using: `start -m <packet-rate> --port 0 --force -f stl/udp_1pkt_src_ip_split_latency.py -t fsize=<packet-size>,lfsize=<packet-size>` where `<packet-rate>` is the RFC2544 throughput expressed in percentage e.g. `100%` or in million packet per second e.g. `9.6mpps`, and `<packet-size>` is the packet size
    2. Go to TUI mode by typing `tui`
    3. Go to Latency view by pressing `l`
    4. A histogram of latency can be toggled by pressing `h`
