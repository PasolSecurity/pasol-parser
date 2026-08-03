# JSON schema

Schema v1 is checked in as [`schemas/parse-result-v1.schema.json`](../schemas/parse-result-v1.schema.json) and [`schemas/error-v1.schema.json`](../schemas/error-v1.schema.json).

Consumers should reject unsupported major versions, tolerate additive fields within a supported major version, and branch on structured warning/error codes rather than message text. Format-specific metadata is intentionally open in the common envelope; each parser owns the shape and semantic version of that metadata.
