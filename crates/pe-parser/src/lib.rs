// Copyright 2026 PasolSecurity contributors
// Licensed under the Apache License, Version 2.0.

#![forbid(unsafe_code)]

use std::collections::{HashMap, HashSet};
use std::panic::{AssertUnwindSafe, catch_unwind};

use goblin::options::ParseMode;
use goblin::pe::PE;
use goblin::pe::certificate_table::AttributeCertificateType;
use goblin::pe::export::Reexport;
use goblin::pe::header;
use goblin::pe::options::ParseOptions;
use goblin::pe::section_table::SectionTable;
use pasol_parser_core::{
    ErrorCode, FileParser, FileType, ParseContext, ParseStatus, ParseWarning, ParserDescriptor,
    ParserError, ParserOutput, Probe,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub static DESCRIPTOR: ParserDescriptor = ParserDescriptor {
    id: "pasol-pe-parser",
    version: env!("CARGO_PKG_VERSION"),
};

#[derive(Debug, Default)]
pub struct PeParser;

impl FileParser for PeParser {
    fn descriptor(&self) -> &'static ParserDescriptor {
        &DESCRIPTOR
    }

    fn probe(&self, input: &[u8]) -> Probe {
        probe_pe(input)
    }

    fn parse(&self, input: &[u8], context: &mut ParseContext) -> Result<ParserOutput, ParserError> {
        let typed = self.parse_typed(input, context)?;
        let metadata = serde_json::to_value(&typed.metadata)
            .map_err(|error| ParserError::new(ErrorCode::Serialization, error.to_string()))?;
        Ok(ParserOutput {
            file_type: typed.file_type,
            status: typed.status,
            metadata,
            warnings: typed.warnings,
        })
    }
}

impl PeParser {
    pub fn parse_typed(
        &self,
        input: &[u8],
        context: &mut ParseContext,
    ) -> Result<TypedPeOutput, ParserError> {
        preflight(input, context)?;
        context.check_deadline()?;

        let strict_options = ParseOptions::default();
        let strict = catch_unwind(AssertUnwindSafe(|| {
            PE::parse_with_opts(input, &strict_options)
        }))
        .map_err(|_| {
            ParserError::new(ErrorCode::Internal, "goblin panicked while parsing PE data")
        })?;

        let (pe, status, mut warnings) = match strict {
            Ok(pe) => (pe, ParseStatus::Complete, Vec::new()),
            Err(strict_error) => {
                let permissive_options =
                    ParseOptions::default().with_parse_mode(ParseMode::Permissive);
                let permissive = catch_unwind(AssertUnwindSafe(|| {
                    PE::parse_with_opts(input, &permissive_options)
                }))
                .map_err(|_| {
                    ParserError::new(
                        ErrorCode::Internal,
                        "goblin panicked during permissive PE parsing",
                    )
                })?;
                let pe = permissive.map_err(|permissive_error| {
                    ParserError::new(
                        ErrorCode::Malformed,
                        format!(
                            "strict PE parse failed: {strict_error}; permissive parse failed: {permissive_error}"
                        ),
                    )
                })?;
                (
                    pe,
                    ParseStatus::Partial,
                    vec![ParseWarning::new(
                        "pe.permissive_recovery",
                        format!(
                            "strict parsing failed and permissive recovery was used: {strict_error}"
                        ),
                    )],
                )
            }
        };

        context.check_deadline()?;
        let metadata = normalize(&pe, input, context, &mut warnings)?;
        let status = if warnings.is_empty() {
            status
        } else {
            ParseStatus::Partial
        };
        Ok(TypedPeOutput {
            file_type: FileType::new(if pe.is_64 { "pe64" } else { "pe32" }),
            status,
            metadata,
            warnings,
        })
    }
}

pub fn probe_pe(input: &[u8]) -> Probe {
    if input.len() < 2 || &input[..2] != b"MZ" {
        return Probe::Unsupported;
    }
    if input.len() < 0x40 {
        return Probe::Candidate {
            file_type: FileType::new("dos_mz"),
        };
    }
    let pe_offset = u32::from_le_bytes(input[0x3c..0x40].try_into().expect("fixed range")) as usize;
    let Some(signature_end) = pe_offset.checked_add(4) else {
        return Probe::Candidate {
            file_type: FileType::new("dos_mz"),
        };
    };
    if input.get(pe_offset..signature_end) != Some(&b"PE\0\0"[..]) {
        return Probe::Candidate {
            file_type: FileType::new("dos_mz"),
        };
    }
    let magic_offset = match pe_offset.checked_add(24) {
        Some(value) => value,
        None => {
            return Probe::Candidate {
                file_type: FileType::new("dos_mz"),
            };
        }
    };
    let Some(magic_bytes) = input.get(magic_offset..magic_offset.saturating_add(2)) else {
        return Probe::Candidate {
            file_type: FileType::new("dos_mz"),
        };
    };
    let magic = u16::from_le_bytes([magic_bytes[0], magic_bytes[1]]);
    match magic {
        0x10b => Probe::Supported {
            file_type: FileType::new("pe32"),
        },
        0x20b => Probe::Supported {
            file_type: FileType::new("pe64"),
        },
        _ => Probe::Candidate {
            file_type: FileType::new("dos_mz"),
        },
    }
}

fn preflight(input: &[u8], context: &ParseContext) -> Result<(), ParserError> {
    match probe_pe(input) {
        Probe::Supported { .. } => {}
        Probe::Candidate { .. } => {
            return Err(ParserError::new(
                ErrorCode::Malformed,
                "input has an MZ header but not a complete supported PE header",
            ));
        }
        Probe::Unsupported => {
            return Err(ParserError::new(
                ErrorCode::Unsupported,
                "input is not a Portable Executable file",
            ));
        }
    }
    let pe_offset = read_u32(input, 0x3c)? as usize;
    let section_count = read_u16(input, pe_offset + 6)? as usize;
    if section_count > context.limits.max_sections {
        return Err(ParserError::new(
            ErrorCode::LimitExceeded,
            format!(
                "PE declares {section_count} sections; maximum is {}",
                context.limits.max_sections
            ),
        ));
    }
    let optional_size = read_u16(input, pe_offset + 20)? as usize;
    let section_start = pe_offset
        .checked_add(24)
        .and_then(|value| value.checked_add(optional_size))
        .ok_or_else(|| ParserError::new(ErrorCode::Malformed, "section table offset overflow"))?;
    let section_bytes = section_count
        .checked_mul(40)
        .ok_or_else(|| ParserError::new(ErrorCode::Malformed, "section table size overflow"))?;
    let end = section_start
        .checked_add(section_bytes)
        .ok_or_else(|| ParserError::new(ErrorCode::Malformed, "section table extent overflow"))?;
    if end > input.len() {
        return Err(ParserError::new(
            ErrorCode::Malformed,
            "section table extends beyond the file",
        ));
    }
    Ok(())
}

fn read_u16(input: &[u8], offset: usize) -> Result<u16, ParserError> {
    let bytes = input.get(offset..offset.saturating_add(2)).ok_or_else(|| {
        ParserError::new(ErrorCode::Malformed, "unexpected end of PE header")
            .at_offset(offset as u64)
    })?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32(input: &[u8], offset: usize) -> Result<u32, ParserError> {
    let bytes = input.get(offset..offset.saturating_add(4)).ok_or_else(|| {
        ParserError::new(ErrorCode::Malformed, "unexpected end of PE header")
            .at_offset(offset as u64)
    })?;
    Ok(u32::from_le_bytes(
        bytes.try_into().expect("four-byte range"),
    ))
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TypedPeOutput {
    pub file_type: FileType,
    pub status: ParseStatus,
    pub metadata: PeMetadata,
    pub warnings: Vec<ParseWarning>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PeMetadata {
    pub architecture: NumericNameU16,
    pub coff_timestamp: CoffTimestamp,
    pub entry_point_rva: String,
    pub image_base: String,
    pub subsystem: NumericNameU16,
    pub characteristics: u16,
    pub dll_characteristics: u16,
    pub sections: Vec<PeSection>,
    pub imports: Vec<ImportLibrary>,
    pub exports: Vec<PeExport>,
    pub resources: Vec<ResourceEntryFact>,
    pub resource_summary: ResourceSummary,
    pub debug: Vec<DebugEntry>,
    pub authenticode: AuthenticodeFacts,
    pub version_info: Option<VersionInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct NumericNameU16 {
    pub raw: u16,
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct CoffTimestamp {
    pub raw: u32,
    pub utc: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PeSection {
    pub name: String,
    pub name_raw_hex: String,
    pub virtual_address: String,
    pub virtual_size: u32,
    pub raw_offset: String,
    pub raw_size: u32,
    pub characteristics: u32,
    pub permissions: SectionPermissions,
    pub entropy: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SectionPermissions {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ImportLibrary {
    pub dll: String,
    pub functions: Vec<ImportedFunction>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ImportedFunction {
    pub name: Option<String>,
    pub ordinal: Option<u16>,
    pub hint: Option<u16>,
    pub iat_rva: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PeExport {
    pub name: Option<String>,
    pub ordinal: u32,
    pub rva: String,
    pub forwarder: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ResourceSummary {
    pub present: bool,
    pub root_named_entries: u16,
    pub root_id_entries: u16,
    pub version_present: bool,
    pub manifest_present: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ResourceEntryFact {
    pub resource_type: ResourceIdentifier,
    pub name: ResourceIdentifier,
    pub language: ResourceIdentifier,
    pub code_page: u32,
    pub rva: String,
    pub size: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ResourceIdentifier {
    pub id: Option<u32>,
    pub name: Option<String>,
    pub name_raw_hex: Option<String>,
}

impl ResourceIdentifier {
    fn missing() -> Self {
        Self {
            id: None,
            name: None,
            name_raw_hex: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct DebugEntry {
    pub kind: NumericNameU32,
    pub timestamp_raw: u32,
    pub size: u32,
    pub rva: String,
    pub file_offset: String,
    pub codeview: Option<CodeViewInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct NumericNameU32 {
    pub raw: u32,
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct CodeViewInfo {
    pub format: String,
    pub guid_or_signature: String,
    pub age: u32,
    pub pdb_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AuthenticodeFacts {
    pub certificate_table_present: bool,
    pub table_status: String,
    pub certificate_count: usize,
    pub pkcs7_present: bool,
    pub verification: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct VersionInfo {
    pub fixed_file_version: Option<String>,
    pub fixed_product_version: Option<String>,
    pub strings: Vec<VersionString>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct VersionString {
    pub key: String,
    pub value: String,
}

fn normalize(
    pe: &PE<'_>,
    input: &[u8],
    context: &ParseContext,
    warnings: &mut Vec<ParseWarning>,
) -> Result<PeMetadata, ParserError> {
    let coff = pe.header.coff_header;
    let optional = pe
        .header
        .optional_header
        .ok_or_else(|| ParserError::new(ErrorCode::Malformed, "PE image has no optional header"))?;
    let windows = optional.windows_fields;

    let sections = pe
        .sections
        .iter()
        .take(context.limits.max_sections)
        .map(|section| normalize_section(section, input))
        .collect();

    let mut imports: Vec<ImportLibrary> = Vec::new();
    let mut library_indexes: HashMap<String, usize> = HashMap::new();
    for import in pe.imports.iter().take(context.limits.max_imports) {
        context.check_deadline()?;
        let dll = import.dll.to_owned();
        let index = if let Some(index) = library_indexes.get(&dll) {
            *index
        } else {
            if imports.len() >= context.limits.max_import_libraries {
                warnings.push(ParseWarning::new(
                    "limit.import_libraries",
                    "additional import libraries were omitted",
                ));
                break;
            }
            let index = imports.len();
            imports.push(ImportLibrary {
                dll: dll.clone(),
                functions: Vec::new(),
            });
            library_indexes.insert(dll, index);
            index
        };
        let ordinal_only = import.name.starts_with("ORDINAL ");
        imports[index].functions.push(ImportedFunction {
            name: (!ordinal_only).then(|| import.name.to_string()),
            ordinal: ordinal_only.then_some(import.ordinal),
            hint: (!ordinal_only).then_some(import.ordinal),
            iat_rva: hex_address(import.offset as u64),
        });
    }
    if pe.imports.len() > context.limits.max_imports {
        warnings.push(ParseWarning::new(
            "limit.imports",
            format!(
                "{} imports were omitted",
                pe.imports.len() - context.limits.max_imports
            ),
        ));
    }

    let ordinal_base = pe
        .export_data
        .as_ref()
        .map(|data| data.export_directory_table.ordinal_base)
        .unwrap_or(0);
    let exports = pe
        .exports
        .iter()
        .take(context.limits.max_exports)
        .enumerate()
        .map(|(index, export)| PeExport {
            name: export.name.map(ToOwned::to_owned),
            ordinal: ordinal_base.saturating_add(index as u32),
            rva: hex_address(export.rva as u64),
            forwarder: export.reexport.as_ref().map(format_reexport),
        })
        .collect();
    if pe.exports.len() > context.limits.max_exports {
        warnings.push(ParseWarning::new(
            "limit.exports",
            format!(
                "{} exports were omitted",
                pe.exports.len() - context.limits.max_exports
            ),
        ));
    }

    let debug = normalize_debug(pe);
    let resource_summary = pe.resource_data.map_or(
        ResourceSummary {
            present: false,
            root_named_entries: 0,
            root_id_entries: 0,
            version_present: false,
            manifest_present: false,
        },
        |resource| ResourceSummary {
            present: true,
            root_named_entries: resource.image_resource_directory.number_of_named_entries,
            root_id_entries: resource.image_resource_directory.number_of_id_entries,
            version_present: resource.version_info.is_some(),
            manifest_present: resource.manifest_data.is_some(),
        },
    );
    let resources = normalize_resources(pe, input, context, warnings);

    let version_info = pe
        .resource_data
        .and_then(|resource| resource.version_info)
        .map(normalize_version);

    Ok(PeMetadata {
        architecture: NumericNameU16 {
            raw: coff.machine,
            name: machine_name(coff.machine).map(ToOwned::to_owned),
        },
        coff_timestamp: CoffTimestamp {
            raw: coff.time_date_stamp,
            utc: render_timestamp(coff.time_date_stamp),
        },
        entry_point_rva: hex_address(pe.entry as u64),
        image_base: hex_address(pe.image_base),
        subsystem: NumericNameU16 {
            raw: windows.subsystem,
            name: subsystem_name(windows.subsystem).map(ToOwned::to_owned),
        },
        characteristics: coff.characteristics,
        dll_characteristics: windows.dll_characteristics,
        sections,
        imports,
        exports,
        resources,
        resource_summary,
        debug,
        authenticode: AuthenticodeFacts {
            certificate_table_present: !pe.certificates.is_empty(),
            table_status: if pe.certificates.is_empty() {
                "absent".to_owned()
            } else {
                "valid".to_owned()
            },
            certificate_count: pe.certificates.len(),
            pkcs7_present: pe.certificates.iter().any(|certificate| {
                certificate.certificate_type == AttributeCertificateType::PkcsSignedData
            }),
            verification: "not_performed".to_owned(),
        },
        version_info,
    })
}

fn normalize_resources(
    pe: &PE<'_>,
    input: &[u8],
    context: &ParseContext,
    warnings: &mut Vec<ParseWarning>,
) -> Vec<ResourceEntryFact> {
    let Some(optional) = pe.header.optional_header else {
        return Vec::new();
    };
    let Some(directory) = optional.data_directories.get_resource_table() else {
        return Vec::new();
    };
    let Some(base) = rva_to_offset(pe, directory.virtual_address) else {
        warnings.push(ParseWarning::new(
            "pe.resources.invalid_rva",
            "resource directory RVA does not map to file-backed data",
        ));
        return Vec::new();
    };
    let declared_end = base
        .saturating_add(directory.size as usize)
        .min(input.len());
    let mut stack = vec![(0_u32, Vec::<ResourceIdentifier>::new(), 0_usize)];
    let mut visited = HashSet::new();
    let mut resources = Vec::new();
    let mut node_count = 0_usize;
    let mut retained_string_bytes = 0_usize;

    while let Some((relative, path, depth)) = stack.pop() {
        if depth > context.limits.max_resource_depth {
            warnings.push(ParseWarning::new(
                "limit.resource_depth",
                "resource directory depth limit was reached",
            ));
            continue;
        }
        if !visited.insert(relative) {
            warnings.push(ParseWarning::new(
                "pe.resources.cycle",
                "resource directory cycle was ignored",
            ));
            continue;
        }
        let Some(directory_offset) = base.checked_add(relative as usize) else {
            warnings.push(ParseWarning::new(
                "pe.resources.offset_overflow",
                "resource directory offset overflowed",
            ));
            continue;
        };
        if directory_offset.saturating_add(16) > declared_end {
            warnings.push(ParseWarning::new(
                "pe.resources.truncated_directory",
                "resource directory header is truncated",
            ));
            continue;
        }
        let named = read_u16_lossy(input, directory_offset + 12).unwrap_or(0) as usize;
        let ids = read_u16_lossy(input, directory_offset + 14).unwrap_or(0) as usize;
        let count = named.saturating_add(ids);
        let entry_start = directory_offset + 16;
        for index in (0..count).rev() {
            node_count += 1;
            if node_count > context.limits.max_resource_nodes {
                warnings.push(ParseWarning::new(
                    "limit.resource_nodes",
                    "additional resource nodes were omitted",
                ));
                return resources;
            }
            let Some(entry_offset) = index
                .checked_mul(8)
                .and_then(|value| entry_start.checked_add(value))
            else {
                continue;
            };
            if entry_offset.saturating_add(8) > declared_end {
                warnings.push(ParseWarning::new(
                    "pe.resources.truncated_entry",
                    "resource directory entry is truncated",
                ));
                break;
            }
            let name_raw = read_u32_lossy(input, entry_offset).unwrap_or(0);
            let target_raw = read_u32_lossy(input, entry_offset + 4).unwrap_or(0);
            let identifier = parse_resource_identifier(
                input,
                base,
                declared_end,
                name_raw,
                context,
                &mut retained_string_bytes,
                warnings,
            );
            let mut next_path = path.clone();
            next_path.push(identifier);
            let target_relative = target_raw & 0x7fff_ffff;
            if target_raw & 0x8000_0000 != 0 {
                stack.push((target_relative, next_path, depth + 1));
                continue;
            }
            let Some(data_offset) = base.checked_add(target_relative as usize) else {
                continue;
            };
            if data_offset.saturating_add(16) > declared_end {
                warnings.push(ParseWarning::new(
                    "pe.resources.truncated_data_entry",
                    "resource data entry is truncated",
                ));
                continue;
            }
            let rva = read_u32_lossy(input, data_offset).unwrap_or(0);
            let size = read_u32_lossy(input, data_offset + 4).unwrap_or(0);
            let code_page = read_u32_lossy(input, data_offset + 8).unwrap_or(0);
            resources.push(ResourceEntryFact {
                resource_type: next_path
                    .first()
                    .cloned()
                    .unwrap_or_else(ResourceIdentifier::missing),
                name: next_path
                    .get(1)
                    .cloned()
                    .unwrap_or_else(ResourceIdentifier::missing),
                language: next_path
                    .get(2)
                    .cloned()
                    .unwrap_or_else(ResourceIdentifier::missing),
                code_page,
                rva: hex_address(rva as u64),
                size,
            });
        }
    }
    resources
}

fn parse_resource_identifier(
    input: &[u8],
    base: usize,
    declared_end: usize,
    raw: u32,
    context: &ParseContext,
    retained: &mut usize,
    warnings: &mut Vec<ParseWarning>,
) -> ResourceIdentifier {
    if raw & 0x8000_0000 == 0 {
        return ResourceIdentifier {
            id: Some(raw),
            name: None,
            name_raw_hex: None,
        };
    }
    let relative = (raw & 0x7fff_ffff) as usize;
    let Some(offset) = base.checked_add(relative) else {
        return ResourceIdentifier::missing();
    };
    let Some(length) = read_u16_lossy(input, offset).map(|value| value as usize) else {
        warnings.push(ParseWarning::new(
            "pe.resources.invalid_name",
            "resource name length is missing",
        ));
        return ResourceIdentifier::missing();
    };
    let byte_length = length.saturating_mul(2);
    if byte_length > context.limits.max_string_bytes
        || retained.saturating_add(byte_length) > context.limits.max_retained_string_bytes
    {
        warnings.push(ParseWarning::new(
            "limit.resource_name",
            "resource name exceeded the configured string budget",
        ));
        return ResourceIdentifier::missing();
    }
    let start = offset.saturating_add(2);
    let end = start.saturating_add(byte_length);
    if end > declared_end || end > input.len() {
        warnings.push(ParseWarning::new(
            "pe.resources.truncated_name",
            "resource name is truncated",
        ));
        return ResourceIdentifier::missing();
    }
    *retained += byte_length;
    let raw_bytes = &input[start..end];
    let units: Vec<u16> = raw_bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect();
    ResourceIdentifier {
        id: None,
        name: Some(String::from_utf16_lossy(&units)),
        name_raw_hex: Some(hex::encode(raw_bytes)),
    }
}

fn rva_to_offset(pe: &PE<'_>, rva: u32) -> Option<usize> {
    if let Some(optional) = pe.header.optional_header {
        if rva < optional.windows_fields.size_of_headers {
            return Some(rva as usize);
        }
    }
    pe.sections.iter().find_map(|section| {
        let start = section.virtual_address;
        let span = section.virtual_size.max(section.size_of_raw_data);
        let delta = rva.checked_sub(start)?;
        if delta >= span || delta >= section.size_of_raw_data {
            return None;
        }
        (section.pointer_to_raw_data as usize).checked_add(delta as usize)
    })
}

fn read_u16_lossy(input: &[u8], offset: usize) -> Option<u16> {
    let bytes = input.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32_lossy(input: &[u8], offset: usize) -> Option<u32> {
    let bytes = input.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes(bytes.try_into().ok()?))
}

fn normalize_section(section: &SectionTable, input: &[u8]) -> PeSection {
    let name_end = section.name.iter().position(|byte| *byte == 0).unwrap_or(8);
    let name_bytes = &section.name[..name_end];
    let name = section
        .real_name
        .clone()
        .unwrap_or_else(|| String::from_utf8_lossy(name_bytes).into_owned());
    let raw_start = section.pointer_to_raw_data as usize;
    let raw_end = raw_start.saturating_add(section.size_of_raw_data as usize);
    let entropy = input.get(raw_start..raw_end).and_then(shannon_entropy);
    PeSection {
        name,
        name_raw_hex: hex::encode(name_bytes),
        virtual_address: hex_address(section.virtual_address as u64),
        virtual_size: section.virtual_size,
        raw_offset: hex_address(section.pointer_to_raw_data as u64),
        raw_size: section.size_of_raw_data,
        characteristics: section.characteristics,
        permissions: SectionPermissions {
            read: section.characteristics & 0x4000_0000 != 0,
            write: section.characteristics & 0x8000_0000 != 0,
            execute: section.characteristics & 0x2000_0000 != 0,
        },
        entropy,
    }
}

fn shannon_entropy(bytes: &[u8]) -> Option<f64> {
    if bytes.is_empty() {
        return None;
    }
    let mut frequencies = [0_u64; 256];
    for byte in bytes {
        frequencies[*byte as usize] += 1;
    }
    let length = bytes.len() as f64;
    let entropy = frequencies
        .into_iter()
        .filter(|count| *count != 0)
        .map(|count| {
            let probability = count as f64 / length;
            -probability * probability.log2()
        })
        .sum::<f64>();
    Some((entropy * 1_000_000.0).round() / 1_000_000.0)
}

fn normalize_debug(pe: &PE<'_>) -> Vec<DebugEntry> {
    let Some(debug) = pe.debug_data.as_ref() else {
        return Vec::new();
    };
    debug
        .entries()
        .filter_map(Result::ok)
        .map(|entry| {
            let codeview = if entry.data_type == goblin::pe::debug::IMAGE_DEBUG_TYPE_CODEVIEW {
                debug
                    .codeview_pdb70_debug_info
                    .map(|info| CodeViewInfo {
                        format: "pdb70".to_owned(),
                        guid_or_signature: hex::encode(info.signature),
                        age: info.age,
                        pdb_path: trim_nul_lossy(info.filename),
                    })
                    .or_else(|| {
                        debug.codeview_pdb20_debug_info.map(|info| CodeViewInfo {
                            format: "pdb20".to_owned(),
                            guid_or_signature: format!("0x{:08x}", info.signature),
                            age: info.age,
                            pdb_path: trim_nul_lossy(info.filename),
                        })
                    })
            } else {
                None
            };
            DebugEntry {
                kind: NumericNameU32 {
                    raw: entry.data_type,
                    name: debug_type_name(entry.data_type).map(ToOwned::to_owned),
                },
                timestamp_raw: entry.time_date_stamp,
                size: entry.size_of_data,
                rva: hex_address(entry.address_of_raw_data as u64),
                file_offset: hex_address(entry.pointer_to_raw_data as u64),
                codeview,
            }
        })
        .collect()
}

fn normalize_version(version: goblin::pe::resource::VersionInfo<'_>) -> VersionInfo {
    let info = version.string_info;
    let candidates = [
        ("Comments", info.comments()),
        ("CompanyName", info.company_name()),
        ("FileDescription", info.file_description()),
        ("FileVersion", info.file_version()),
        ("InternalName", info.internal_name()),
        ("LegalCopyright", info.legal_copyright()),
        ("LegalTrademarks", info.legal_trademarks()),
        ("OriginalFilename", info.original_filename()),
        ("PrivateBuild", info.private_build()),
        ("ProductName", info.product_name()),
        ("ProductVersion", info.product_version()),
        ("SpecialBuild", info.special_build()),
    ];
    VersionInfo {
        fixed_file_version: version
            .fixed_info
            .map(|fixed| fixed.file_version().to_string()),
        fixed_product_version: version
            .fixed_info
            .map(|fixed| fixed.product_version().to_string()),
        strings: candidates
            .into_iter()
            .filter_map(|(key, value)| {
                value.map(|value| VersionString {
                    key: key.to_owned(),
                    value,
                })
            })
            .collect(),
    }
}

fn format_reexport(reexport: &Reexport<'_>) -> String {
    match reexport {
        Reexport::DLLName { export, lib } => format!("{lib}.{export}"),
        Reexport::DLLOrdinal { ordinal, lib } => format!("{lib}.#{ordinal}"),
    }
}

fn trim_nul_lossy(bytes: &[u8]) -> String {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

fn hex_address(value: u64) -> String {
    format!("0x{value:x}")
}

fn render_timestamp(timestamp: u32) -> Option<String> {
    let seconds = u64::from(timestamp);
    let days = i64::try_from(seconds / 86_400).ok()?;
    let seconds_in_day = seconds % 86_400;
    let hour = seconds_in_day / 3_600;
    let minute = (seconds_in_day % 3_600) / 60;
    let second = seconds_in_day % 60;

    // Howard Hinnant's bounded civil-from-days conversion for the proleptic
    // Gregorian calendar. A u32 Unix timestamp is always within its range.
    let shifted = days.checked_add(719_468)?;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    Some(format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z"
    ))
}

fn machine_name(machine: u16) -> Option<&'static str> {
    match machine {
        header::COFF_MACHINE_X86 => Some("x86"),
        header::COFF_MACHINE_X86_64 => Some("x86_64"),
        header::COFF_MACHINE_ARM => Some("arm"),
        header::COFF_MACHINE_ARM64 => Some("arm64"),
        header::COFF_MACHINE_IA64 => Some("ia64"),
        header::COFF_MACHINE_RISCV32 => Some("riscv32"),
        header::COFF_MACHINE_RISCV64 => Some("riscv64"),
        _ => None,
    }
}

fn subsystem_name(subsystem: u16) -> Option<&'static str> {
    match subsystem {
        0 => Some("unknown"),
        1 => Some("native"),
        2 => Some("windows_gui"),
        3 => Some("windows_cui"),
        7 => Some("posix_cui"),
        9 => Some("windows_ce_gui"),
        10 => Some("efi_application"),
        11 => Some("efi_boot_service_driver"),
        12 => Some("efi_runtime_driver"),
        13 => Some("efi_rom"),
        14 => Some("xbox"),
        16 => Some("windows_boot_application"),
        _ => None,
    }
}

fn debug_type_name(kind: u32) -> Option<&'static str> {
    match kind {
        0 => Some("unknown"),
        1 => Some("coff"),
        2 => Some("codeview"),
        3 => Some("fpo"),
        4 => Some("misc"),
        5 => Some("exception"),
        16 => Some("repro"),
        17 => Some("embedded_portable_pdb"),
        19 => Some("pdb_checksum"),
        20 => Some("extended_dll_characteristics"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pasol_parser_sdk::fixture_builder::{minimal_pe32, minimal_pe64};

    #[test]
    fn identifies_content_not_extension() {
        assert!(matches!(probe_pe(b"not a PE"), Probe::Unsupported));
        assert!(matches!(probe_pe(b"MZ"), Probe::Candidate { .. }));
    }

    #[test]
    fn entropy_is_bounded() {
        assert_eq!(shannon_entropy(&[]), None);
        assert_eq!(shannon_entropy(&[0; 32]), Some(0.0));
        assert_eq!(shannon_entropy(&[0, 1, 2, 3]), Some(2.0));
    }

    #[test]
    fn timestamps_are_rendered_without_external_parsing() {
        assert_eq!(render_timestamp(0).as_deref(), Some("1970-01-01T00:00:00Z"));
        assert_eq!(
            render_timestamp(1_704_067_200).as_deref(),
            Some("2024-01-01T00:00:00Z")
        );
        assert_eq!(
            render_timestamp(u32::MAX).as_deref(),
            Some("2106-02-07T06:28:15Z")
        );
    }

    #[test]
    fn parses_minimal_pe32_and_pe64() {
        for (bytes, expected) in [(minimal_pe32(), "pe32"), (minimal_pe64(), "pe64")] {
            let output = PeParser
                .parse_typed(&bytes, &mut ParseContext::new(Default::default()))
                .expect("minimal PE should parse");
            assert_eq!(output.file_type.0, expected);
            assert_eq!(output.metadata.sections.len(), 1);
            assert_eq!(output.metadata.sections[0].name, ".text");
        }
    }
}
