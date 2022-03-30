# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

export OBJS := $(abspath ./bin/)
export BPFTOOL ?= bpftool
LIBBPF_SRC := $(abspath ./libbpf/src)
LIBBPF_OBJ := $(abspath $(OUTPUT)/libbpf.a)
export ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' | sed 's/mips.*/mips/')
export GENERATED_INCLUDE_FOLDER := $(abspath $(OBJS)/include/$(ARCH))
SRC := ./src

export TARGET = daq

all: $(LIBBPF_OBJ) $(GENERATED_INCLUDE_FOLDER)/vmlinux.h $(TARGET)

$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) 
	$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1 OBJDIR=$(OBJS)/libbpf DESTDIR=$(OBJS) INCLUDEDIR= LIBDIR= UAPIDIR= install

$(GENERATED_INCLUDE_FOLDER)/vmlinux.h:
	mkdir -p $(GENERATED_INCLUDE_FOLDER)
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $(GENERATED_INCLUDE_FOLDER)/vmlinux.h

$(TARGET):
	$(MAKE) -C $(SRC)

.PHONY: clean
clean:
	$(MAKE) -C $(LIBBPF_SRC) clean
	$(MAKE) -C $(SRC) clean
	rm -rf $(OBJS)
