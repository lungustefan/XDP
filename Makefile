CLANG ?= clang
CC ?= gcc
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
MULTIARCH_INC := /usr/include/$(shell uname -m)-linux-gnu
CFLAGS ?= -O2 -g -Wall -Wextra
BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH) -I$(MULTIARCH_INC)
INCLUDES := -Isrc
LIBS := -lbpf -lelf -lz

all: src/xdp_ddos_kern.o xdp_ddos

src/xdp_ddos_kern.o: src/xdp_ddos_kern.c src/common.h
	$(CLANG) $(BPF_CFLAGS) $(INCLUDES) -c $< -o $@

xdp_ddos: src/xdp_ddos_user.c src/common.h
	$(CC) $(CFLAGS) $(INCLUDES) $< -o $@ $(LIBS)

clean:
	rm -f xdp_ddos src/xdp_ddos_kern.o

.PHONY: all clean
