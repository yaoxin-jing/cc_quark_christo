arch = $(shell uname -m)
kernel := ../build/qkernel.bin
tdx_kernel = ../build/qkernel_tdx.bin
kernel_debug := ../build/qkernel_d.bin
tdx_kernel_debug := ../build/qkernel_d_tdx.bin
target ?= $(arch)-qkernel
qkernel := ../target/$(target)/release/libqkernel.a
qkernel_debug := ../target/$(target)/debug/libqkernel.a

linker_script := src/qlib/kernel/arch/$(arch)/linker.ld
assembly_source_files := $(wildcard src/qlib/kernel/arch/$(arch)/*.s)
assembly_object_files := $(patsubst src/qlib/kernel/arch/$(arch)/%.s, \
	../build/arch/$(arch)/%.o, $(assembly_source_files))

all: $(kernel)

release: $(kernel)

debug: $(kernel_debug)

tdx_release: $(tdx_kernel)

tdx_debug: $(tdx_kernel_debug)

$(kernel): kernel $(assembly_object_files)
	@ld --gc-sections -T $(linker_script) -o $(kernel) \
		$(assembly_object_files) $(qkernel)

$(kernel_debug): kernel_debug $(assembly_object_files)
	@ld --gc-sections -T $(linker_script) -o $(kernel_debug) \
		$(assembly_object_files) $(qkernel_debug)

$(tdx_kernel): tdx_kernel $(assembly_object_files)
	@ld -n --gc-sections -T $(linker_script) -o $(kernel) \
		$(assembly_object_files) $(qkernel)

$(tdx_kernel_debug): tdx_kernel_debug $(assembly_object_files)
	@ld -n --gc-sections -T $(linker_script) -o $(kernel_debug) \
		$(assembly_object_files) $(qkernel_debug)

kernel:
	CARGO_TARGET_DIR=../target cargo +$(TOOLCHAIN) build --target $(arch)-qkernel.json --release

kernel_debug:
	CARGO_TARGET_DIR=../target cargo +$(TOOLCHAIN) build --target $(arch)-qkernel.json

tdx_kernel:
	CARGO_TARGET_DIR=../target cargo +$(TOOLCHAIN) build --target $(arch)-qkernel.json --release --features tdx

tdx_kernel_debug:
	CARGO_TARGET_DIR=../target cargo +$(TOOLCHAIN) build --target $(arch)-qkernel.json --features tdx

../build/arch/$(arch)/%.o: src/qlib/kernel/arch/$(arch)/%.s
	@mkdir -p $(shell dirname $@)
	$(AS) $^ -o $@

