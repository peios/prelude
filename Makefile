SHELL := bash
.SHELLFLAGS := -eu -o pipefail -c

# Use the rustup toolchain explicitly. On NixOS the default cargo/rustc
# come from a nix-shimmed rustc-wrapper that can't find the musl rustlib,
# so `cargo build` fails even though `rustup target list --installed`
# shows musl. Going straight to the rustup-managed binaries dodges that.
RUSTUP_TC := $(HOME)/.rustup/toolchains/stable-x86_64-unknown-linux-gnu
CARGO     := $(RUSTUP_TC)/bin/cargo
RUSTC     := $(RUSTUP_TC)/bin/rustc
export CARGO RUSTC

# Put the rustup toolchain ahead of the Nix-shimmed binaries on PATH so
# cargo's own resolution of `rustc`, `rust-lld`, etc. picks the rustup
# versions consistently.
export PATH := $(RUSTUP_TC)/bin:$(PATH)

TARGET := x86_64-unknown-linux-musl
BIN    := target/$(TARGET)/release/prelude

.PHONY: all build clean

all: build

build:
	$(CARGO) build --release

clean:
	$(CARGO) clean
