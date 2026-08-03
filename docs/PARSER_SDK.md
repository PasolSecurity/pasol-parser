# Parser SDK guide

Implement `pasol_parser_core::FileParser` with a static descriptor, a cheap byte-based `probe`, and a bounded `parse`. A parser receives a `ParseContext`; call `check_deadline` inside potentially large loops and use every relevant `ParserLimits` field before retaining data.

```rust
use pasol_parser_core::{FileParser, ParseContext, ParserError, ParserOutput};

fn parse_bounded(
    parser: &dyn FileParser,
    bytes: &[u8],
    context: &mut ParseContext,
) -> Result<ParserOutput, ParserError> {
    context.check_deadline()?;
    parser.parse(bytes, context)
}
```

The SDK contains `DeterministicExampleParser` and `fixture_builder`, which generates minimal harmless PE32 and PE32+ inputs in memory. Tests should cover empty, truncated, corrupt, misleading-extension, extreme-count, and near-limit cases. Fuzz targets belong under `fuzz/fuzz_targets` and must never depend on private or malicious corpora.

## Error convention

Use `Unsupported` when bytes are not your format, `Malformed` when required structure is invalid, `LimitExceeded` before resource use crosses a cap, `Timeout` when the context deadline expires, and `Internal` only for contained implementation failures. Include a checked input offset where it is useful. Recoverable omissions should be `ParseWarning` entries and set status to `partial`.

## Output convention

Metadata is factual JSON. Stable identifiers use snake case. Numeric addresses and sizes are JSON integers when lossless; warning offsets are hexadecimal strings. Do not include analysis labels such as suspicious, benign, malicious, or safe.
