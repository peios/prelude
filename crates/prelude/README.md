# Prelude Runtime

This crate implements the initramfs process 1. Boot hooks mount the real
root at `/mnt/rootfs`; Prelude verifies the mount, moves the kernel virtual
filesystems, clears the old initramfs, and executes the selected init.

See [the repository overview](../../README.md),
[architecture](../../docs/architecture.md), and
[build instructions](../../docs/building.md). The maintained command and
hook references are in [docs/man](../../docs/man/).

Run unit tests through Bazel. Do not execute this crate's main program on
the development host.
