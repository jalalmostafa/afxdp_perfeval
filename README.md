# eBPF-DAQ

## Test Environment

Run `./testenv.sh` with no parameter to get a list of available commands, or
run `./testenv.sh --help` to get the full help listing with all options. The
script can maintain several environments active at the same time, and you
can switch between them using the `--name` option.

If you don't specify a name, the most recently used environment will be
used. If you don't specify a name when setting up a new environment, a
random name will be generated for you.

Examples:

Setup new environment named "test": `./testenv.sh setup --name=test`

Create a shell alias for easy use of script from anywhere: `eval $(./testenv.sh alias)`

See the currently active environment, and a list of all active environment
names (with alias defined as above): `t status`

Enter the currently active environment: `t enter`

Execute a command inside the environment: `t exec -- ip a`

Teardown the environment: `t teardown`


## Build

### Ubuntu

```bash
apt install clang llvm libelf-dev libpcap-dev gcc-multilib build-essential linux-tools-common linux-tools-generic linux-headers-$(uname -r)
make
```