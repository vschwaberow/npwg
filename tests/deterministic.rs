// SPDX-License-Identifier: MIT

use npwg::{
    generate_deterministic_password, generate_deterministic_password_versioned,
    DeterministicVersion, PasswordGeneratorError,
};
use serde::Deserialize;

#[derive(Deserialize)]
struct Vector {
    name: String,
    username: Option<String>,
    length: usize,
    alphabet: String,
    expected: String,
}

#[test]
fn deterministic_v2_vectors() {
    let vectors: Vec<Vector> = serde_json::from_str(include_str!("deterministic_v2.json")).unwrap();
    for vector in vectors {
        let alphabet: Vec<_> = vector.alphabet.chars().collect();
        let actual = generate_deterministic_password_versioned(
            "master-password",
            "example.com",
            vector.username.as_deref(),
            1,
            vector.length,
            &alphabet,
            DeterministicVersion::V2,
        )
        .unwrap();
        assert_eq!(actual, vector.expected, "{}", vector.name);
        assert_eq!(actual.chars().count(), vector.length, "{}", vector.name);
    }
}

#[test]
fn deterministic_rejects_empty_alphabet() {
    for version in [DeterministicVersion::V1, DeterministicVersion::V2] {
        let result = generate_deterministic_password_versioned(
            "master",
            "service",
            None,
            1,
            0,
            &[],
            version,
        );
        assert!(matches!(
            result,
            Err(PasswordGeneratorError::InvalidConfig(_))
        ));
    }
}

#[test]
fn deterministic_preserves_zero_length() {
    for version in [DeterministicVersion::V1, DeterministicVersion::V2] {
        assert_eq!(
            generate_deterministic_password_versioned(
                "master",
                "service",
                None,
                1,
                0,
                &['a'],
                version
            )
            .unwrap(),
            ""
        );
    }
}

#[test]
fn deterministic_v1_rejects_large_alphabet() {
    let alphabet: Vec<_> = (0x100..=0x200)
        .map(|i| char::from_u32(i).unwrap())
        .collect();
    let result = generate_deterministic_password("master", "service", None, 1, 1, &alphabet);
    assert!(matches!(
        result,
        Err(PasswordGeneratorError::InvalidConfig(_))
    ));
}

#[test]
fn deterministic_v1_vectors() {
    let vectors: Vec<Vector> = serde_json::from_str(include_str!("deterministic_v1.json")).unwrap();
    for vector in vectors {
        let alphabet: Vec<_> = vector.alphabet.chars().collect();
        let actual = generate_deterministic_password(
            "master-password",
            "example.com",
            vector.username.as_deref(),
            1,
            vector.length,
            &alphabet,
        )
        .unwrap();
        assert_eq!(actual, vector.expected, "{}", vector.name);
    }
}
