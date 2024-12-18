.PHONY: debug release cuda_debug cuda_release snp_debug snp_release

debug:
	CARGO_TARGET_DIR=../target cargo +$(TOOLCHAIN) build

release:
	CARGO_TARGET_DIR=../target cargo +$(TOOLCHAIN) build --release

cuda_debug:
	CARGO_TARGET_DIR=../target cargo +$(TOOLCHAIN) build --features cuda

cuda_release:
	CARGO_TARGET_DIR=../target cargo +$(TOOLCHAIN) build --release --features cuda

snp_debug:
	CARGO_TARGET_DIR=../target cargo +$(TOOLCHAIN) build --features snp

snp_release:
	CARGO_TARGET_DIR=../target cargo +$(TOOLCHAIN) build --release --features snp