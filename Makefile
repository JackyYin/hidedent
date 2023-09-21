BPF_PROG = hidedent

CLANG ?= clang

LIBBPF_DIR ?= libbpf
LIBBPF_OUTPUT_DIR ?= $(shell pwd)/output/libbpf

BPFTOOL_DIR ?= bpftool
BPFTOOL_OUTPUT_DIR ?= $(shell pwd)/output/bpftool/
BPFTOOL_BIN = $(BPFTOOL_OUTPUT_DIR)/bpftool

VMLINUX ?= vmlinux.h

all: $(BPF_PROG)

$(LIBBPF_DIR):
	git clone https://github.com/libbpf/libbpf.git $(LIBBPF_DIR)
	mkdir -p $(LIBBPF_OUTPUT_DIR)
	BUILD_STATIC_ONLY=y DESTDIR=$(LIBBPF_OUTPUT_DIR) make -C libbpf/src install

$(BPFTOOL_DIR):
	git clone --recurse-submodules https://github.com/libbpf/bpftool.git $(BPFTOOL_DIR)
	cd $(BPFTOOL_DIR) && git submodule update --init

$(BPFTOOL_BIN): $(BPFTOOL_DIR)
	mkdir -p $(BPFTOOL_OUTPUT_DIR)
	OUTPUT=$(BPFTOOL_OUTPUT_DIR) make -C $(BPFTOOL_DIR)/src

$(VMLINUX): $(BPFTOOL_BIN)
	$(BPFTOOL_BIN) btf dump file /sys/kernel/btf/vmlinux format c > $@

$(BPF_PROG).bpf.o: $(BPF_PROG).bpf.c $(VMLINUX) $(BPFTOOL_BIN)
	$(CLANG) -target bpf \
		-I$(BPFTOOL_OUTPUT_DIR)libbpf/include \
		-idirafter /usr/include/aarch64-linux-gnu \
		-O2 -g -Wall \
		-c $< -o $@

$(BPF_PROG): $(BPF_PROG).c $(BPF_PROG).bpf.o
	$(CC) \
		-I$(BPFTOOL_OUTPUT_DIR)libbpf/include \
		-L$(BPFTOOL_OUTPUT_DIR)libbpf \
		-O2 -g -Wall \
		$< -o $@ -lbpf -lelf -lz

run: $(BPF_PROG)
	./$(BPF_PROG)

clean:
	rm -rf $(LIBBPF_OUTPUT_DIR) $(LIBBPF_DIR)
	rm -rf $(BPFTOOL_OUTPUT_DIR) $(BPFTOOL_DIR)
	rm -rf *.o
	rm -rf $(BPF_PROG)
	rm -rf $(VMLINUX)
