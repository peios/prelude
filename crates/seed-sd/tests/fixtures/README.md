# Bootstrap Descriptor Fixture

`bootstrap.sd` is the 116-byte output of Prelude's original `build_seed_sd`
at commit `75c909adf61c52f04efa8a23759f9e513570474a`, compiled with the
committed Cargo.lock and vendored libp-sd. It was captured before migrating
the helper to peios-rs. The test compares the complete wire representation,
including ACE order and inheritance flags.

SHA-256: `d01e20fd6621762527fde5eef4ac6a19b26c52a2940bffc9e45df42e33c5ddaa`.
