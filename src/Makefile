TOOL_NAME    := daq
XDP_TARGETS  := bpf/xsk.bpf
USER_TARGETS := daq
# XDP_TARGETS  := xdpsock_kern
# USER_TARGETS := xdpsock_user
TEST_FILE    := 

LIB_DIR       = $(abspath ../xdp-tools/lib)
USER_LIBS    := -lpthread
MAN_PAGE     := 

## add DEFINES=-DRX_DROP to make to build rxdrop
CFLAGS += -g -std=gnu11 -I$(realpath .) $(DEFINES)
BPF_CFLAGS += -I$(realpath .)

include $(LIB_DIR)/common.mk
