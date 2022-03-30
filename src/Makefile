# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

CLANG ?= clang
LLVM_STRIP ?= llvm-strip
VMLINUX := $(GENERATED_INCLUDE_FOLDER)/vmlinux.h
INCLUDES := -I$(OBJS) -I../libbpf/include/uapi -I$(GENERATED_INCLUDE_FOLDER)
CFLAGS := -g -Wall
LDFLAGS := -L$(OBJS) -l:libbpf.a -lelf -lz

# Get Clang's default includes on this system. We'll explicitly add these dirs
# to the includes list when compiling with `-target bpf` because otherwise some
# architecture-specific dirs will be "missing" on some architectures/distros -
# headers such as asm/types.h, asm/byteorder.h, asm/socket.h, asm/sockios.h,
# sys/cdefs.h etc. might be missing.
#
# Use '-idirafter': Don't interfere with include mechanics except where the
# build would have failed anyways.
CLANG_BPF_SYS_INCLUDES = $(shell $(CLANG) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

ifeq ($(V),1)
	Q =
	msg =
else
	Q = @
	msg = @printf '  %-8s %s%s\n'					\
		      "$(1)"						\
		      "$(patsubst $(abspath $(OBJS))/%,%,$(2))"	\
		      "$(if $(3), $(3))";
	MAKEFLAGS += --no-print-directory
endif

.PHONY: all
all: $(TARGET)

.PHONY: clean
clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(OBJS) $(TARGET)

# Build BPF code
$(OBJS)/daq.bpf.o: daq.bpf.c
	$(call msg,BPF,$@)
	$(Q)$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -c $< -o $@
	$(Q)$(LLVM_STRIP) -g $@

# Generate BPF skeletons
$(OBJS)/daq.skel.h: $(OBJS)/daq.bpf.o
	$(call msg,GEN-SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< > $@

$(OBJS)/daq.o: daq.c $(wildcard %.h)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@

# Build application binary
$(TARGET): $(OBJS)/daq.bpf.o $(OBJS)/daq.skel.h $(OBJS)/daq.o
	$(call msg,BINARY,$@)
	$(Q)$(CC) $(CFLAGS) $(OBJS)/daq.o $(LDFLAGS) -o $(OBJS)/$@

# delete failed targets
.DELETE_ON_ERROR:

# keep intermediate (.skel.h, .bpf.o, etc) targets
.SECONDARY:
