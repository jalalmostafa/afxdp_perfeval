TOOL_NAME    := xdpsock
# XDP_TARGETS  := bpf/xsk.bpf
XDP_TARGETS  := bpf/xsk.bpf
USER_TARGETS := daq
TEST_FILE    := 

LIB_DIR       = $(abspath ../xdp-tools/lib)
USER_LIBS    := -lpthread
MAN_PAGE     := 
# EXTRA_USER_DEPS := tcpip/inet_csum.o tcpip/icmp4.o xsk.o

CFLAGS += -g -std=gnu11 -I$(realpath .)


include $(LIB_DIR)/common.mk

$(EXTRA_USER_DEPS): ${EXTRA_USER_DEPS:.o=.c}
	$(QUIET_CC)$(CC) $(CFLAGS) -O -c $< -o $@
