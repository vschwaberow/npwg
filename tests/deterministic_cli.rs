// SPDX-License-Identifier: MIT

use std::process::{Command, Stdio};

#[test]
fn invalid_deterministic_versions_fail_before_password_prompt() {
    let cases: &[&[&str]] = &[
        &["--deterministic", "--service", "example.com"],
        &["--deterministic-version", "v2"],
        &[
            "--deterministic",
            "--deterministic-version",
            "v3",
            "--service",
            "example.com",
        ],
    ];
    for args in cases {
        let output = Command::new(env!("CARGO_BIN_EXE_npwg"))
            .args(*args)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(stderr.contains("--deterministic-version"), "{stderr}");
        assert!(!stderr.contains("Master password"), "{stderr}");
    }
}
