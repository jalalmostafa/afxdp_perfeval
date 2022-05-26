# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

LIBDQDK_VERSION := 0.0.1
LIBDQDK_MAJOR_VERSION := $(shell echo $(LIBDQDK_VERSION) | sed 's/\..*//')
BUILD_STATIC_ONLY := 1

ifeq ("$(origin V)", "command line")
  VERBOSE = $(V)
endif
ifndef VERBOSE
  VERBOSE = 0
endif
ifeq ($(VERBOSE),1)
  export Q =
else
  export Q = @
endif
ifeq ($(VERBOSE),0)
MAKEFLAGS += --no-print-directory
endif

DEFINES +=

ifeq ($(VERBOSE), 0)
    export QUIET_CC       = @echo '    CC       '$@;
    export QUIET_CLANG    = @echo '    CLANG    '$@;
    export QUIET_LLC      = @echo '    LLC      '$@;
    export QUIET_LINK     = @echo '    LINK     '$@;
    export QUIET_INSTALL  = @echo '    INSTALL  '$@;
    export QUIET_M4       = @echo '    M4       '$@;
    export QUIET_GEN      = @echo '    GEN      '$@;
endif

ifneq ($(PRODUCTION),1)
DEFINES += -DDEBUG
endif

PREFIX?=/usr/local
LIBDIR?=$(PREFIX)/lib
SBINDIR?=$(PREFIX)/sbin
HDRDIR?=$(PREFIX)/include/dqdk
DATADIR?=$(PREFIX)/share
MANDIR?=$(DATADIR)/man

LIBXDP_LIB_DIR = $(realpath ./xdp-tools/lib/libxdp)

CLANG = clang
LLC = llc
BPF_TARGET = bpf
LDFLAGS += -L${LIBXDP_LIB_DIR}
LDLIBS += -l:xdp
CWARNINGS := -Wall -Wextra -Werror -Wno-maybe-uninitialized
CFLAGS += -g -O3 -std=gnu11 -I$(realpath xdp-tools/lib/libbpf/src/root/usr/include/) $(CWARNINGS) $(DEFINES)
BPF_CFLAGS += -I$(realpath xdp-tools/lib/libbpf/src/root/usr/include/) -I$(realpath xdp-tools/lib/libbpf/include/uapi/linux) $(DEFINES)


LIB_DIR = ./lib

export OBJDIR ?= $(realpath ./build)
HEADER_DIR = ./include
SHARED_OBJDIR := $(OBJDIR)/sharedobjs
STATIC_OBJDIR := $(OBJDIR)/staticobjs
OBJS := dqdk.o
XDP_OBJS := udpfilter.bpf.o
SHARED_OBJS := $(addprefix $(SHARED_OBJDIR)/,$(OBJS))
STATIC_OBJS := $(addprefix $(STATIC_OBJDIR)/,$(OBJS))
STATIC_LIBS := $(OBJDIR)/libdqdk.a

TEST_DIR := tests
TEST_FILE := $(TEST_DIR)/demo/demo.c
export TEST_CFLAGS := $(CFLAGS) -I$(realpath $(HEADER_DIR)) -L$(realpath $(OBJDIR)) -Wall -Werror $(LDFLAGS)
export TEST_LDLIBS := -L$(realpath $(OBJDIR)) -l:dqdk

SHARED_CFLAGS += -fPIC -DSHARED
LIB_HEADERS := $(HEADER_DIR)

CFLAGS += -I$(HEADER_DIR)
BPF_CFLAGS += -I$(HEADER_DIR)


ifndef BUILD_STATIC_ONLY
SHARED_LIBS := $(OBJDIR)/libdqdk.so \
	       $(OBJDIR)/libdqdk.so.$(LIBDQDK_MAJOR_VERSION) \
	       $(OBJDIR)/libdqdk.so.$(LIBDQDK_VERSION)
VERSION_SCRIPT := libdqdk.map
endif

all: $(STATIC_LIBS) $(SHARED_LIBS) $(OBJDIR)/$(XDP_OBJS)

clean:
	$(Q)rm -f $(STATIC_LIBS) $(STATIC_OBJS) $(SHARED_LIBS) $(SHARED_OBJS) $(OBJDIR)/$(XDP_OBJS) $(OBJDIR)/*.ll
	$(Q)for d in $(SHARED_OBJDIR) $(STATIC_OBJDIR); do \
		[ -d "$$d" ] && rmdir "$$d"; done || true
	$(Q)$(MAKE) -C tests clean

install: all
	$(Q)install -d -m 0755 $(DESTDIR)$(HDRDIR)
	$(Q)install -d -m 0755 $(DESTDIR)$(LIBDIR)
	$(Q)install -d -m 0755 $(DESTDIR)$(LIBDIR)/pkgconfig
	$(Q)install -d -m 0755 $(DESTDIR)$(BPF_OBJECT_DIR)
	$(Q)install -m 0644 $(LIB_HEADERS) $(DESTDIR)$(HDRDIR)/
	$(Q)install -m 0644 $(PC_FILE) $(DESTDIR)$(LIBDIR)/pkgconfig/
	$(Q)cp -fpR $(SHARED_LIBS) $(STATIC_LIBS) $(DESTDIR)$(LIBDIR)
	$(Q)install -m 0755 $(OBJDIR)/$(XDP_OBJS) $(DESTDIR)$(BPF_OBJECT_DIR)
	$(if $(MAN_FILES),$(Q)install -m 0755 -d $(DESTDIR)$(MANDIR)/man3)
	$(if $(MAN_FILES),$(Q)install -m 0644 $(MAN_FILES) $(DESTDIR)$(MANDIR)/man3)


$(OBJDIR)/libdqdk.a: $(STATIC_OBJS)
	$(QUIET_LINK)$(AR) rcs $@ $^

$(OBJDIR)/libdqdk.so: $(OBJDIR)/libdqdk.so.$(LIBDQDK_MAJOR_VERSION)
	$(Q)ln -sf $(^F) $@

$(OBJDIR)/libdqdk.so.$(LIBDQDK_MAJOR_VERSION): $(OBJDIR)/libdqdk.so.$(LIBDQDK_VERSION)
	$(Q)ln -sf $(^F) $@

$(OBJDIR)/libdqdk.so.$(LIBDQDK_VERSION): $(SHARED_OBJS)
	$(QUIET_LINK)$(CC) -shared -Wl,-soname,libdqdk.so.$(LIBDQDK_MAJOR_VERSION) \
		      $^ $(LDFLAGS) $(LDLIBS) -o $@

$(STATIC_OBJDIR):
	$(Q)mkdir -p $(STATIC_OBJDIR)

$(SHARED_OBJDIR):
	$(Q)mkdir -p $(SHARED_OBJDIR)

$(STATIC_OBJDIR)/%.o: $(LIB_DIR)/%.c | $(STATIC_OBJDIR)
	$(QUIET_CC)$(CC) $(CFLAGS) -c $< -o $@

$(SHARED_OBJDIR)/%.o: $(LIB_DIR)/%.c | $(SHARED_OBJDIR)
	$(QUIET_CC)$(CC) $(CFLAGS) $(SHARED_CFLAGS) -c $< -o $@

$(OBJDIR)/$(XDP_OBJS): $(OBJDIR)/%.o: $(LIB_DIR)/bpf/%.c
	$(QUIET_CLANG)$(CLANG) -S \
	    -target $(BPF_TARGET) \
	    -D __BPF_TRACING__ \
	    $(BPF_CFLAGS) \
	    -Wall \
	    -Wno-unused-value \
	    -Wno-pointer-sign \
	    -Wno-compare-distinct-pointer-types \
	    -Werror \
	    -O2 -emit-llvm -c -g -o ${@:.o=.ll} $<
	$(QUIET_LLC)$(LLC) -march=$(BPF_TARGET) -filetype=obj -o $@ ${@:.o=.ll}

.PHONY: tests
tests: all
	$(Q)$(MAKE) -C $(TEST_DIR)
