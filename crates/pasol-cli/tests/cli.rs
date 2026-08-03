// Copyright 2026 PasolSecurity contributors
// Licensed under the Apache License, Version 2.0.

#![forbid(unsafe_code)]

use std::fs;
use std::process::Command;

use pasol_parser_sdk::fixture_builder::minimal_pe64;

#[test]
fn inspect_identify_and_hash_minimal_pe() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("misleading.txt");
    fs::write(&path, minimal_pe64()).expect("write PE fixture");
    let binary = env!("CARGO_BIN_EXE_pasol");

    let identify = Command::new(binary)
        .args(["identify", path.to_str().expect("utf8 temp path")])
        .output()
        .expect("run identify");
    assert!(identify.status.success());
    assert_eq!(String::from_utf8_lossy(&identify.stdout).trim(), "pe64");

    let inspect = Command::new(binary)
        .args([
            "inspect",
            path.to_str().expect("utf8 temp path"),
            "--format",
            "json",
        ])
        .output()
        .expect("run inspect");
    assert!(
        inspect.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&inspect.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&inspect.stdout).expect("valid JSON report");
    assert_eq!(report["schema_version"], "1.0.0");
    assert_eq!(report["file_type"], "pe64");
    assert_eq!(report["metadata"]["architecture"]["name"], "x86_64");
    assert_eq!(report["metadata"]["sections"][0]["name"], ".text");

    let hash = Command::new(binary)
        .args(["hash", path.to_str().expect("utf8 temp path")])
        .output()
        .expect("run hash");
    assert!(hash.status.success());
    assert_eq!(String::from_utf8_lossy(&hash.stdout).trim().len(), 64);
}

#[test]
fn malformed_file_returns_stable_error() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("broken.exe");
    fs::write(&path, b"MZ").expect("write malformed fixture");
    let output = Command::new(env!("CARGO_BIN_EXE_pasol"))
        .args([
            "inspect",
            path.to_str().expect("utf8 temp path"),
            "--format",
            "json",
        ])
        .output()
        .expect("run inspect");
    assert_eq!(output.status.code(), Some(4));
    assert!(output.stdout.is_empty());
    let error: serde_json::Value =
        serde_json::from_slice(&output.stderr).expect("valid JSON error");
    assert_eq!(error["error"]["code"], "malformed");
}
