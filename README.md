# Pasol Parser

A memory-safe, extensible Rust framework for parsing Windows executable files and producing normalized security metadata.

Phase 1 deliberately reports facts, not malware verdicts. The parser never executes or loads the inspected file, does not fetch symbols, and does not verify signatures over a network.

## Quick start

```console
cargo run -p pasol-cli -- inspect sample.exe
cargo run -p pasol-cli -- inspect sample.exe --format json
cargo run -p pasol-cli -- identify unknown.bin
cargo run -p pasol-cli -- hash unknown.bin
```

The CLI identifies content from magic bytes rather than extensions. `inspect` runs parsing in an isolated worker with a five-second deadline and bounded input/metadata limits. JSON follows the versioned schemas in [`schemas/`](schemas/).

## Workspace

- `parser-core`: versioned parser contract, limits, identification, hashing, errors, and normalized envelope.
- `pe-parser`: factual PE32/PE32+ metadata using `goblin` plus independent boundary checks.
- `parser-sdk`: contributor API, deterministic example parser, and harmless PE fixture builder.
- `pasol-cli`: end-user commands and worker isolation.

See [Architecture](docs/ARCHITECTURE.md), [Security model](docs/SECURITY_MODEL.md), and [SDK guide](docs/PARSER_SDK.md). The roadmap is in [ROADMAP.md](ROADMAP.md).

## Supported metadata

Architecture, COFF timestamp, entry point, image base, subsystem, sections and entropy, permissions, imports, exports, bounded resource entries, CodeView/debug facts, Authenticode table presence, and fixed file-version facts. No field is a claim that a file is safe or malicious.

## Development

Rust 1.85 or newer is supported. Run:

```console
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

Contributions are accepted under Apache-2.0 and require a Developer Certificate of Origin sign-off (`git commit -s`). Harmless synthetic fixtures only—never submit malware.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
