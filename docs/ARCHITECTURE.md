# Architecture

## Trust boundary

An input file is untrusted from its first byte. The public CLI reads only regular files, rejects inputs over 256 MiB, and sends bytes to a child worker. The parent enforces a five-second wall-clock deadline; Unix workers also set an address-space limit and Windows workers attempt a Job Object working-set limit. Parser-level counters, string budgets, checked offsets, and output-size caps remain authoritative on every platform.

## Data flow

```text
path -> bounded read -> magic-byte probe -> isolated worker -> parser contract
     -> factual metadata + structured warnings -> schema-v1 JSON
```

`parser-core` owns the stable envelope and safety contract. Format crates return format-specific JSON metadata through that contract. `pasol-cli` owns process isolation and presentation. `parser-sdk` gives third-party parsers the same interface and test tools.

## PE lifecycle

1. Independently validate DOS and PE signatures, optional-header magic, section count, and table extent.
2. Ask `goblin` for high-level structures in strict mode; retry permissively only when safe and emit a warning.
3. Normalize fields under explicit budgets. Resource traversal is iterative, depth-limited, cycle-aware, and never retains resource payloads.
4. Return `complete`, or `partial` when recovery produced warnings. Structurally unsafe inputs return a typed error.

## Versioning

`schema_version` versions the JSON envelope; `parser_version` versions parsing behavior. Schema v1 fields are additive within the major version. Removing or changing a field's meaning requires schema v2. Warnings have stable machine-readable codes and explanatory messages.

## Non-goals

Phase 1 does not classify malware, recursively unpack archives, fetch PDBs, validate Authenticode trust, extract resource blobs, or execute inspected content.
