TOOL_NAME       := dqdk
XDP_TARGETS     := bpf/xsk.bpf bpf/rr2.bpf bpf/rr4.bpf bpf/rr8.bpf
USER_TARGETS    := dqdk
EXTRA_USER_DEPS := tcpip/* dlog.h dqdk.h
TEST_FILE       := 

LIB_DIR          = $(abspath ../xdp-tools/lib)
USER_LIBS       := -lpthread
MAN_PAGE        :=

## add USER_DEFINES=-Dflag to make to build daq with some flag where flag can be:
##    NO_HGPG           Disable Hugepages
##    UDP_MODE          L3/L4 checksumming
##    UMEM_UNALIGNED    Use unaligned memory
##
USER_DEFINES    +=
CFLAGS          += -I$(realpath .) $(USER_DEFINES)
BPF_CFLAGS      += -I$(realpath .)

include $(LIB_DIR)/common.mk
