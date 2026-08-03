# Security model

## Guarantees

- Extensions are ignored for identification.
- No inspected file is executed, mapped as a program, or dynamically loaded.
- File size, table counts, traversal depth, retained strings, metadata, warnings, and time are capped.
- Arithmetic derived from file data is checked before slicing or allocation.
- Panics from the third-party PE decoder are contained and converted to internal errors.
- Malformed files fail safely or produce explicitly partial output with warnings.

Default limits are documented in [`ParserLimits`](../crates/parser-core/src/lib.rs). Applications embedding the libraries must enforce their own process-level deadline and memory controls; the CLI supplies a reference implementation.

## Platform caveat

The five-second CLI deadline is enforced by the parent process. Unix applies an address-space rlimit. Windows attempts to place the worker in a Job Object with a working-set cap; systems that reject that policy still retain all parser/file/output bounds and the hard deadline. This limitation is intentionally documented rather than presented as a universal hard memory guarantee.

## Explicit exclusions

Authenticode output means only that a structurally parseable certificate table is present. It is not chain, identity, revocation, or integrity verification. Debug output is factual and local; the parser never follows a PDB path. Resource data is summarized, not returned.

See [SECURITY.md](../SECURITY.md) for private reporting.
