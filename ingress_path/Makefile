CLANG ?= clang
LLC ?= llc
STRIP ?= llvm-strip
BPFTOOL ?= bpftool
GCC ?= gcc
VMLINUX_BTF ?= /sys/kernel/btf/vmlinux

LIBBPF_DIR ?= /usr/include

OUTPUT := .
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

INCLUDES := -I$(OUTPUT) -I/usr/include -I$(LIBBPF_DIR)
CFLAGS := -g -O2 -Wall $(INCLUDES)
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)

.PHONY: all clean vmlinux.h

all: tcp_rate_limit.o tcp_rate_limit_loader

vmlinux.h:
	bpftool btf dump file $(VMLINUX_BTF) format c > vmlinux.h

tcp_rate_limit.o: tcp_rate_limit.c vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c tcp_rate_limit.c -o tcp_rate_limit.o
	$(STRIP) -g tcp_rate_limit.o
	@echo "TCP rate limit BPF object created: tcp_rate_limit.o"

tcp_rate_limit_loader.o: tcp_rate_limit_loader.c
	$(GCC) $(CFLAGS) -c tcp_rate_limit_loader.c -o tcp_rate_limit_loader.o
	@echo "TCP rate limit loader object created: tcp_rate_limit_loader.o"

tcp_rate_limit_loader: tcp_rate_limit_loader.o
	$(GCC) -o tcp_rate_limit_loader tcp_rate_limit_loader.o -lbpf -lelf -lz
	@echo "TCP rate limit loader executable created: ./tcp_rate_limit_loader"

clean:
	@echo "Cleaning build artifacts..."
	rm -f ./tcp_rate_limit.o ./tcp_rate_limit_loader.o ./tcp_rate_limit_loader
	@echo "Clean complete"
