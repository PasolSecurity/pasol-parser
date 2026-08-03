#![no_main]

use libfuzzer_sys::fuzz_target;
use pasol_parser_core::{ParserLimits, inspect_bytes};
use pasol_pe_parser::PeParser;

fuzz_target!(|data: &[u8]| {
    let mut limits = ParserLimits::default();
    limits.max_file_size = 1024 * 1024;
    limits.max_sections = 32;
    limits.max_imports = 2048;
    limits.max_exports = 2048;
    limits.max_resource_nodes = 2048;
    limits.max_serialized_metadata = 2 * 1024 * 1024;
    let _ = inspect_bytes(&PeParser, data, limits);
});
