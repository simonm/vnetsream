CLANG ?= clang
CFLAGS := -O2 -g -Wall -Werror $(CFLAGS)
KERNEL_VERSION := $(shell uname -r)
KERNEL_HEADERS := /usr/lib/modules/$(KERNEL_VERSION)/build
INCLUDES := -I$(KERNEL_HEADERS)/include \
           -I$(KERNEL_HEADERS)/include/uapi \
           -I$(KERNEL_HEADERS)/include/generated/uapi \
           -I$(KERNEL_HEADERS)/arch/x86/include \
           -I$(KERNEL_HEADERS)/arch/x86/include/generated \
           -I$(shell dirname $(shell which clang))/../lib/clang/$(shell clang --version | grep 'clang version' | cut -d' ' -f3)/include

all: ebpf/tls_monitor.o v-netstream

ebpf/tls_monitor.o: ebpf/tls_monitor.c ebpf/tls_monitor.h
	$(CLANG) \
		-target bpf \
		-D__TARGET_ARCH_x86 \
		$(CFLAGS) \
		$(INCLUDES) \
		-c $< \
		-o $@

v-netstream: ebpf/tls_monitor.o
	go build -o v-netstream ./cmd/vnetstream

clean:
	rm -f ebpf/tls_monitor.o v-netstream

.PHONY: all clean
