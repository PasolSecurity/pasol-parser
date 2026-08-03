// Copyright 2026 PasolSecurity contributors
// Licensed under the Apache License, Version 2.0.

use criterion::{Criterion, criterion_group, criterion_main};
use pasol_parser_core::{ParserLimits, inspect_bytes};
use pasol_parser_sdk::fixture_builder;
use pasol_pe_parser::PeParser;

fn benchmark_minimal_pe(criterion: &mut Criterion) {
    let pe32 = fixture_builder::minimal_pe32();
    let pe64 = fixture_builder::minimal_pe64();
    let parser = PeParser;
    criterion.bench_function("minimal_pe32", |bencher| {
        bencher.iter(|| inspect_bytes(&parser, &pe32, ParserLimits::default()))
    });
    criterion.bench_function("minimal_pe64", |bencher| {
        bencher.iter(|| inspect_bytes(&parser, &pe64, ParserLimits::default()))
    });
}

criterion_group!(benches, benchmark_minimal_pe);
criterion_main!(benches);
