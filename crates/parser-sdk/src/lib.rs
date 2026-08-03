// Copyright 2026 PasolSecurity contributors
// Licensed under the Apache License, Version 2.0.

#![forbid(unsafe_code)]

pub use pasol_parser_core::*;

pub mod test_support {
    use pasol_parser_core::{FileParser, ParserLimits, Probe, inspect_bytes};

    pub fn assert_deterministic(parser: &dyn FileParser, bytes: &[u8]) {
        let first = inspect_bytes(parser, bytes, ParserLimits::default())
            .expect("first parse should succeed");
        let second = inspect_bytes(parser, bytes, ParserLimits::default())
            .expect("second parse should succeed");
        assert_eq!(
            serde_json::to_vec(&first).expect("serialize first report"),
            serde_json::to_vec(&second).expect("serialize second report")
        );
    }

    pub fn assert_unsupported(parser: &dyn FileParser, bytes: &[u8]) {
        assert!(matches!(parser.probe(bytes), Probe::Unsupported));
    }
}

pub mod fixture_builder {
    const PE_OFFSET: usize = 0x80;
    const FILE_ALIGNMENT: u32 = 0x200;
    const SECTION_ALIGNMENT: u32 = 0x1000;

    pub fn minimal_pe32() -> Vec<u8> {
        build_minimal(false)
    }

    pub fn minimal_pe64() -> Vec<u8> {
        build_minimal(true)
    }

    fn build_minimal(is_64: bool) -> Vec<u8> {
        let optional_size = if is_64 { 0xf0 } else { 0xe0 };
        let mut bytes = vec![0_u8; 0x400];
        bytes[0..2].copy_from_slice(b"MZ");
        put_u32(&mut bytes, 0x3c, PE_OFFSET as u32);
        bytes[PE_OFFSET..PE_OFFSET + 4].copy_from_slice(b"PE\0\0");

        let coff = PE_OFFSET + 4;
        put_u16(&mut bytes, coff, if is_64 { 0x8664 } else { 0x014c });
        put_u16(&mut bytes, coff + 2, 1);
        put_u32(&mut bytes, coff + 4, 1_700_000_000);
        put_u16(&mut bytes, coff + 16, optional_size as u16);
        put_u16(&mut bytes, coff + 18, 0x0022);

        let optional = coff + 20;
        put_u16(&mut bytes, optional, if is_64 { 0x020b } else { 0x010b });
        bytes[optional + 2] = 14;
        put_u32(&mut bytes, optional + 4, FILE_ALIGNMENT);
        put_u32(&mut bytes, optional + 16, 0x1000);
        put_u32(&mut bytes, optional + 20, 0x1000);
        if is_64 {
            put_u64(&mut bytes, optional + 24, 0x0000_0001_4000_0000);
        } else {
            put_u32(&mut bytes, optional + 24, 0x2000);
            put_u32(&mut bytes, optional + 28, 0x0040_0000);
        }
        put_u32(&mut bytes, optional + 32, SECTION_ALIGNMENT);
        put_u32(&mut bytes, optional + 36, FILE_ALIGNMENT);
        put_u16(&mut bytes, optional + 40, 6);
        put_u16(&mut bytes, optional + 48, 6);
        put_u32(&mut bytes, optional + 56, 0x2000);
        put_u32(&mut bytes, optional + 60, FILE_ALIGNMENT);
        put_u16(&mut bytes, optional + 68, 3);
        put_u16(&mut bytes, optional + 70, 0x8140);
        if is_64 {
            put_u64(&mut bytes, optional + 72, 0x10_0000);
            put_u64(&mut bytes, optional + 80, 0x1000);
            put_u64(&mut bytes, optional + 88, 0x10_0000);
            put_u64(&mut bytes, optional + 96, 0x1000);
            put_u32(&mut bytes, optional + 108, 16);
        } else {
            put_u32(&mut bytes, optional + 72, 0x10_0000);
            put_u32(&mut bytes, optional + 76, 0x1000);
            put_u32(&mut bytes, optional + 80, 0x10_0000);
            put_u32(&mut bytes, optional + 84, 0x1000);
            put_u32(&mut bytes, optional + 92, 16);
        }

        let section = optional + optional_size;
        bytes[section..section + 5].copy_from_slice(b".text");
        put_u32(&mut bytes, section + 8, 1);
        put_u32(&mut bytes, section + 12, 0x1000);
        put_u32(&mut bytes, section + 16, FILE_ALIGNMENT);
        put_u32(&mut bytes, section + 20, FILE_ALIGNMENT);
        put_u32(&mut bytes, section + 36, 0x6000_0020);
        bytes[FILE_ALIGNMENT as usize] = 0xc3;
        bytes
    }

    fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
}
