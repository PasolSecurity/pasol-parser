# Contributing

Thank you for helping build trustworthy file parsers.

1. Discuss substantial API or schema changes in an issue first.
2. Fork the repository and create a focused branch.
3. Add tests, including malformed and boundary inputs.
4. Run formatting, Clippy, and the full test suite.
5. Sign every commit with the Developer Certificate of Origin: `git commit -s`.
6. Open a pull request describing security and compatibility implications.

All contributions must be Apache-2.0 compatible. By signing off, you certify the [Developer Certificate of Origin 1.1](https://developercertificate.org/).

## Parser requirements

- Identify from bytes, never an extension.
- Do not execute, dynamically load, or recursively unpack input.
- Treat every length, count, offset, and string as untrusted.
- Use checked arithmetic and configured caps before allocating.
- Prefer partial factual output with structured warnings when safe.
- Never produce malware/safety verdicts in parser crates.
- Add fuzz coverage and harmless, documented fixture provenance.

See [docs/PARSER_SDK.md](docs/PARSER_SDK.md) for the contract and conventions.
