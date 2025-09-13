KERNEL_DIR ?= $(HOME)/src/linux
BPF_CPPFLAGS := -I$(KERNEL_DIR)/usr/include

.PHONY: all
all: chdir_setns.so progs.bpf.o

%.so: %.c
	$(CC) -Wall -Wextra -fPIC -shared -o $@ $< -ldl

%.bpf.o: %.bpf.c
	clang $(BPF_CPPFLAGS) -Wall -Wextra -target bpf -O2 -ggdb -c -o $@ $<
