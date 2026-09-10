// SPDX-License-Identifier: MIT

use npwg::generate_deterministic_password;
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
