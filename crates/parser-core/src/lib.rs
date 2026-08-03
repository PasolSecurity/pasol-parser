// Copyright 2026 PasolSecurity contributors
// Licensed under the Apache License, Version 2.0.

#![forbid(unsafe_code)]

use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;
use std::time::{Duration, Instant};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const SCHEMA_VERSION: &str = "1.0.0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParserDescriptor {
    pub id: &'static str,
    pub version: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Probe {
    Unsupported,
    Candidate { file_type: FileType },
    Supported { file_type: FileType },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
pub struct FileType(pub String);

impl FileType {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }
}

impl fmt::Display for FileType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Debug, Clone)]
pub struct ParserLimits {
    pub max_file_size: u64,
    pub max_sections: usize,
    pub max_import_libraries: usize,
    pub max_imports: usize,
    pub max_exports: usize,
    pub max_resource_nodes: usize,
    pub max_resource_depth: usize,
    pub max_string_bytes: usize,
    pub max_retained_string_bytes: usize,
    pub max_version_bytes: usize,
    pub max_warnings: usize,
    pub max_serialized_metadata: usize,
    pub timeout: Duration,
}

impl Default for ParserLimits {
    fn default() -> Self {
        Self {
            max_file_size: 256 * 1024 * 1024,
            max_sections: 96,
            max_import_libraries: 4_096,
            max_imports: 65_536,
            max_exports: 65_536,
            max_resource_nodes: 16_384,
            max_resource_depth: 8,
            max_string_bytes: 16 * 1024,
            max_retained_string_bytes: 8 * 1024 * 1024,
            max_version_bytes: 4 * 1024 * 1024,
            max_warnings: 256,
            max_serialized_metadata: 32 * 1024 * 1024,
            timeout: Duration::from_secs(5),
        }
    }
}

#[derive(Debug)]
pub struct ParseContext {
    pub limits: ParserLimits,
    deadline: Instant,
}

impl ParseContext {
    pub fn new(limits: ParserLimits) -> Self {
        let deadline = Instant::now() + limits.timeout;
        Self { limits, deadline }
    }

    pub fn check_deadline(&self) -> Result<(), ParserError> {
        if Instant::now() > self.deadline {
            return Err(ParserError::new(
                ErrorCode::Timeout,
                "the parser deadline was exceeded",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ParseStatus {
    Complete,
    Partial,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ParseWarning {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<String>,
}

impl ParseWarning {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            offset: None,
        }
    }

    pub fn at_offset(mut self, offset: u64) -> Self {
        self.offset = Some(format!("0x{offset:x}"));
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ParserOutput {
    pub file_type: FileType,
    pub status: ParseStatus,
    pub metadata: Value,
    pub warnings: Vec<ParseWarning>,
}

pub trait FileParser: Send + Sync {
    fn descriptor(&self) -> &'static ParserDescriptor;
    fn probe(&self, input: &[u8]) -> Probe;
    fn parse(&self, input: &[u8], context: &mut ParseContext) -> Result<ParserOutput, ParserError>;
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ParseResult {
    pub schema_version: String,
    pub parser: String,
    pub parser_version: String,
    pub file_type: FileType,
    pub sha256: String,
    pub size: u64,
    pub status: ParseStatus,
    pub metadata: Value,
    pub warnings: Vec<ParseWarning>,
}

pub fn inspect_bytes(
    parser: &dyn FileParser,
    input: &[u8],
    limits: ParserLimits,
) -> Result<ParseResult, ParserError> {
    if input.len() as u64 > limits.max_file_size {
        return Err(ParserError::new(
            ErrorCode::LimitExceeded,
            format!("file exceeds the {} byte limit", limits.max_file_size),
        ));
    }
    let mut context = ParseContext::new(limits.clone());
    let output = parser.parse(input, &mut context)?;
    let metadata_size = serde_json::to_vec(&output.metadata)
        .map_err(|error| ParserError::new(ErrorCode::Serialization, error.to_string()))?
        .len();
    if metadata_size > limits.max_serialized_metadata {
        return Err(ParserError::new(
            ErrorCode::LimitExceeded,
            "serialized metadata exceeds its configured limit",
        ));
    }
    let descriptor = parser.descriptor();
    Ok(ParseResult {
        schema_version: SCHEMA_VERSION.to_owned(),
        parser: descriptor.id.to_owned(),
        parser_version: descriptor.version.to_owned(),
        file_type: output.file_type,
        sha256: sha256_bytes(input),
        size: input.len() as u64,
        status: output.status,
        metadata: output.metadata,
        warnings: cap_warnings(output.warnings, limits.max_warnings),
    })
}

pub fn cap_warnings(mut warnings: Vec<ParseWarning>, maximum: usize) -> Vec<ParseWarning> {
    if warnings.len() <= maximum {
        return warnings;
    }
    let retained = maximum.saturating_sub(1);
    warnings.truncate(retained);
    warnings.push(ParseWarning::new(
        "warnings.suppressed",
        "additional warnings were suppressed",
    ));
    warnings
}

pub fn sha256_bytes(input: &[u8]) -> String {
    hex::encode(Sha256::digest(input))
}

pub fn sha256_file(path: &Path) -> Result<String, ParserError> {
    let mut file = open_regular_file(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer).map_err(ParserError::io)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hex::encode(hasher.finalize()))
}

pub fn read_limited_file(path: &Path, maximum: u64) -> Result<Vec<u8>, ParserError> {
    let file = open_regular_file(path)?;
    let declared = file.metadata().map_err(ParserError::io)?.len();
    if declared > maximum {
        return Err(ParserError::new(
            ErrorCode::LimitExceeded,
            format!("file exceeds the {maximum} byte limit"),
        ));
    }
    let capacity = usize::try_from(declared.min(maximum)).map_err(|_| {
        ParserError::new(
            ErrorCode::LimitExceeded,
            "file size does not fit this platform",
        )
    })?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .map_err(|_| ParserError::new(ErrorCode::LimitExceeded, "file allocation failed"))?;
    file.take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(ParserError::io)?;
    if bytes.len() as u64 > maximum {
        return Err(ParserError::new(
            ErrorCode::LimitExceeded,
            "file grew beyond the configured limit while it was read",
        ));
    }
    Ok(bytes)
}

fn open_regular_file(path: &Path) -> Result<File, ParserError> {
    let file = File::open(path).map_err(ParserError::io)?;
    if !file.metadata().map_err(ParserError::io)?.is_file() {
        return Err(ParserError::new(
            ErrorCode::Io,
            "input path is not a regular file",
        ));
    }
    Ok(file)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    Io,
    Unsupported,
    Malformed,
    LimitExceeded,
    Timeout,
    Serialization,
    Internal,
}

#[derive(Debug, Error)]
#[error("{message}")]
pub struct ParserError {
    pub code: ErrorCode,
    pub message: String,
    pub offset: Option<u64>,
}

impl ParserError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            offset: None,
        }
    }

    pub fn at_offset(mut self, offset: u64) -> Self {
        self.offset = Some(offset);
        self
    }

    pub fn io(error: io::Error) -> Self {
        Self::new(ErrorCode::Io, error.to_string())
    }
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct ErrorEnvelope {
    pub schema_version: String,
    pub error: ErrorBody,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct ErrorBody {
    pub code: ErrorCode,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<String>,
}

impl From<&ParserError> for ErrorEnvelope {
    fn from(error: &ParserError) -> Self {
        Self {
            schema_version: SCHEMA_VERSION.to_owned(),
            error: ErrorBody {
                code: error.code,
                message: error.message.clone(),
                offset: error.offset.map(|value| format!("0x{value:x}")),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_known_value() {
        assert_eq!(
            sha256_bytes(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn caps_warning_count() {
        let warnings = (0..10)
            .map(|index| ParseWarning::new("test", index.to_string()))
            .collect();
        let warnings = cap_warnings(warnings, 3);
        assert_eq!(warnings.len(), 3);
        assert_eq!(warnings[2].code, "warnings.suppressed");
    }
}
