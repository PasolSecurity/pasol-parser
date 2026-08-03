// Copyright 2026 PasolSecurity contributors
// Licensed under the Apache License, Version 2.0.

#![forbid(unsafe_code)]

use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

use clap::{Parser, Subcommand, ValueEnum};
use pasol_parser_core::{
    ErrorCode, ErrorEnvelope, FileParser, ParseResult, ParserError, ParserLimits, Probe,
    inspect_bytes, read_limited_file, sha256_file,
};
use pasol_pe_parser::PeParser;
use tempfile::NamedTempFile;
use wait_timeout::ChildExt;

const WORKER_MEMORY_LIMIT: u64 = 768 * 1024 * 1024;

#[derive(Debug, Parser)]
#[command(
    name = "pasol",
    version,
    about = "Safely inspect Windows executable files"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Inspect a file and report factual metadata.
    Inspect {
        path: PathBuf,
        #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
        format: OutputFormat,
    },
    /// Identify a file by its contents.
    Identify { path: PathBuf },
    /// Calculate a file's SHA-256 hash.
    Hash { path: PathBuf },
    #[command(name = "__worker", hide = true)]
    Worker { path: PathBuf },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormat {
    Human,
    Json,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let code = match cli.command {
        Commands::Inspect { path, format } => run_inspect_parent(&path, format),
        Commands::Identify { path } => run_identify(&path),
        Commands::Hash { path } => run_hash(&path),
        Commands::Worker { path } => run_worker(&path),
    };
    ExitCode::from(code as u8)
}

fn run_inspect_parent(path: &Path, format: OutputFormat) -> i32 {
    match inspect_via_worker(path) {
        Ok(worker) if worker.code == 0 => match format {
            OutputFormat::Json => {
                print!("{}", worker.output);
                0
            }
            OutputFormat::Human => match serde_json::from_str::<ParseResult>(&worker.output) {
                Ok(report) => {
                    print_human(&report);
                    0
                }
                Err(error) => {
                    eprintln!("internal error: worker returned invalid JSON: {error}");
                    1
                }
            },
        },
        Ok(worker) => {
            match format {
                OutputFormat::Json => eprint!("{}", worker.output),
                OutputFormat::Human => print_worker_error(&worker.output),
            }
            worker.code
        }
        Err(error) => {
            print_error(&error, format);
            exit_code(&error)
        }
    }
}

struct WorkerResult {
    code: i32,
    output: String,
}

fn inspect_via_worker(path: &Path) -> Result<WorkerResult, ParserError> {
    let executable = std::env::current_exe().map_err(ParserError::io)?;
    let mut output_file = NamedTempFile::new().map_err(ParserError::io)?;
    let worker_stdout = output_file.reopen().map_err(ParserError::io)?;
    let mut child = Command::new(executable)
        .arg("__worker")
        .arg(path)
        .stdin(Stdio::null())
        .stdout(Stdio::from(worker_stdout))
        .stderr(Stdio::null())
        .spawn()
        .map_err(ParserError::io)?;

    let timeout = ParserLimits::default().timeout;
    let status = match child.wait_timeout(timeout).map_err(ParserError::io)? {
        Some(status) => status,
        None => {
            child.kill().map_err(ParserError::io)?;
            let _ = child.wait();
            return Err(ParserError::new(
                ErrorCode::Timeout,
                "inspection exceeded the 5 second worker deadline",
            ));
        }
    };

    output_file
        .as_file_mut()
        .seek(SeekFrom::Start(0))
        .map_err(ParserError::io)?;
    let mut output = String::new();
    output_file
        .as_file_mut()
        .read_to_string(&mut output)
        .map_err(ParserError::io)?;
    if output.is_empty() {
        return Err(ParserError::new(
            ErrorCode::LimitExceeded,
            "the parser worker exited without a report, likely due to a resource limit",
        ));
    }
    Ok(WorkerResult {
        code: status.code().unwrap_or(1),
        output,
    })
}

fn run_worker(path: &Path) -> i32 {
    let _memory_guard = match install_memory_limit() {
        Ok(guard) => guard,
        Err(error) => return write_worker_error(&error),
    };
    let limits = ParserLimits::default();
    let result = read_limited_file(path, limits.max_file_size)
        .and_then(|bytes| inspect_bytes(&PeParser, &bytes, limits));
    match result {
        Ok(report) => match serde_json::to_string(&report) {
            Ok(json) => {
                println!("{json}");
                0
            }
            Err(error) => write_worker_error(&ParserError::new(
                ErrorCode::Serialization,
                error.to_string(),
            )),
        },
        Err(error) => write_worker_error(&error),
    }
}

fn write_worker_error(error: &ParserError) -> i32 {
    let envelope = ErrorEnvelope::from(error);
    let json = serde_json::to_string(&envelope).unwrap_or_else(|_| {
        "{\"schema_version\":\"1.0.0\",\"error\":{\"code\":\"internal\",\"message\":\"failed to serialize error\"}}".to_owned()
    });
    println!("{json}");
    let _ = std::io::stdout().flush();
    exit_code(error)
}

fn run_identify(path: &Path) -> i32 {
    let limits = ParserLimits::default();
    match read_limited_file(path, limits.max_file_size) {
        Ok(bytes) if bytes.is_empty() => {
            println!("empty");
            0
        }
        Ok(bytes) => {
            let file_type = match PeParser.probe(&bytes) {
                Probe::Supported { file_type } | Probe::Candidate { file_type } => file_type.0,
                Probe::Unsupported => "unknown".to_owned(),
            };
            println!("{file_type}");
            0
        }
        Err(error) => {
            eprintln!("{}", error.message);
            exit_code(&error)
        }
    }
}

fn run_hash(path: &Path) -> i32 {
    match sha256_file(path) {
        Ok(hash) => {
            println!("{hash}");
            0
        }
        Err(error) => {
            eprintln!("{}", error.message);
            exit_code(&error)
        }
    }
}

fn print_human(report: &ParseResult) {
    println!("Parser:       {} {}", report.parser, report.parser_version);
    println!("File type:    {}", report.file_type);
    println!("SHA-256:      {}", report.sha256);
    println!("Size:         {} bytes", report.size);
    println!("Status:       {:?}", report.status);
    if let Some(architecture) = report.metadata.get("architecture") {
        let name = architecture
            .get("name")
            .and_then(|value| value.as_str())
            .unwrap_or("unknown");
        println!("Architecture: {name}");
    }
    if let Some(entry) = report
        .metadata
        .get("entry_point_rva")
        .and_then(|value| value.as_str())
    {
        println!("Entry point:  {entry}");
    }
    let section_count = report
        .metadata
        .get("sections")
        .and_then(|value| value.as_array())
        .map_or(0, Vec::len);
    let import_count = report
        .metadata
        .get("imports")
        .and_then(|value| value.as_array())
        .map_or(0, Vec::len);
    let export_count = report
        .metadata
        .get("exports")
        .and_then(|value| value.as_array())
        .map_or(0, Vec::len);
    println!("Sections:     {section_count}");
    println!("Import DLLs:  {import_count}");
    println!("Exports:      {export_count}");
    if !report.warnings.is_empty() {
        println!("Warnings:");
        for warning in &report.warnings {
            println!("  [{}] {}", warning.code, warning.message);
        }
    }
}

fn print_worker_error(json: &str) {
    match serde_json::from_str::<serde_json::Value>(json) {
        Ok(value) => {
            let message = value
                .pointer("/error/message")
                .and_then(|value| value.as_str())
                .unwrap_or("inspection failed");
            eprintln!("{message}");
        }
        Err(_) => eprintln!("inspection failed"),
    }
}

fn print_error(error: &ParserError, format: OutputFormat) {
    match format {
        OutputFormat::Human => eprintln!("{}", error.message),
        OutputFormat::Json => {
            let envelope = ErrorEnvelope::from(error);
            if let Ok(json) = serde_json::to_string(&envelope) {
                eprintln!("{json}");
            }
        }
    }
}

fn exit_code(error: &ParserError) -> i32 {
    match error.code {
        ErrorCode::Io => 3,
        ErrorCode::Unsupported | ErrorCode::Malformed => 4,
        ErrorCode::LimitExceeded | ErrorCode::Timeout => 5,
        ErrorCode::Serialization | ErrorCode::Internal => 1,
    }
}

#[cfg(windows)]
struct MemoryGuard {
    _job: Option<win32job::Job>,
}

#[cfg(windows)]
fn install_memory_limit() -> Result<MemoryGuard, ParserError> {
    let mut info = win32job::ExtendedLimitInfo::new();
    info.limit_working_memory(1024 * 1024, WORKER_MEMORY_LIMIT as usize);
    let job = match win32job::Job::create_with_limit_info(&info) {
        Ok(job) if job.assign_current_process().is_ok() => Some(job),
        _ => None,
    };
    Ok(MemoryGuard { _job: job })
}

#[cfg(unix)]
struct MemoryGuard;

#[cfg(unix)]
fn install_memory_limit() -> Result<MemoryGuard, ParserError> {
    rlimit::Resource::AS
        .set(WORKER_MEMORY_LIMIT, WORKER_MEMORY_LIMIT)
        .map_err(|error| {
            ParserError::new(
                ErrorCode::Internal,
                format!("cannot set parser memory limit: {error}"),
            )
        })?;
    Ok(MemoryGuard)
}

#[cfg(not(any(windows, unix)))]
struct MemoryGuard;

#[cfg(not(any(windows, unix)))]
fn install_memory_limit() -> Result<MemoryGuard, ParserError> {
    Err(ParserError::new(
        ErrorCode::Internal,
        "worker memory limits are unsupported on this platform",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn exit_codes_are_stable() {
        assert_eq!(exit_code(&ParserError::new(ErrorCode::Io, "x")), 3);
        assert_eq!(exit_code(&ParserError::new(ErrorCode::Malformed, "x")), 4);
        assert_eq!(exit_code(&ParserError::new(ErrorCode::Timeout, "x")), 5);
    }

    #[test]
    fn hashes_regular_file() {
        let directory = tempfile::tempdir().expect("temp directory");
        let path = directory.path().join("sample.bin");
        fs::write(&path, b"abc").expect("write sample");
        assert_eq!(run_hash(&path), 0);
    }
}
