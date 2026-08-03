# Harmless test data

This project creates deterministic minimal PE32 and PE32+ fixtures in memory through `pasol-parser-sdk::fixture_builder`. No malware, production binaries, or copyrighted third-party executables are stored here.

Unit and integration suites mutate those synthetic bytes to cover empty inputs, truncation, corrupt signatures, impossible section tables, extreme counts, and misleading filenames. New checked-in fixtures require a provenance entry describing how they were generated and a SHA-256 digest.
