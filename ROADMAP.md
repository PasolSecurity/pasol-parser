# Roadmap

## Phase 1 — parser foundation

- [x] Versioned parser interface and normalized JSON envelope
- [x] Content identification, SHA-256, and bounded file reads
- [x] PE headers, sections, imports, exports, resources, debug, signature presence, and version facts
- [x] Isolated CLI worker, deadline, and resource caps
- [x] Malformed-input tests, fuzz targets, benchmarks, and stable schema v1
- [x] Contributor, security, CI, and release foundations

## Phase 2 — feature and detection plugins

- Versioned feature-extraction contract
- Sandboxed detection plugins
- YARA-X integration
- Explainable findings distinct from parser facts

## Later

- Additional Windows formats where threat modeling justifies them
- Split crates into repositories only when contributor scale requires it
- Reproducible packages and broader platform builds
