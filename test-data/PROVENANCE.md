# Fixture provenance

There are currently no checked-in binary fixtures. All inputs are generated from original, public Rust source in `crates/parser-sdk/src/lib.rs` and exist only during tests. They contain a DOS stub/header, one PE header, one `.text` section, and a single return opcode; they are not built from third-party programs and perform no file, network, or process activity.
