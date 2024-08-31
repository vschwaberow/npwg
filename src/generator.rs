// SPDX-License-Identifier: MIT
// Project: npwg
// File: src/generator.rs
// Author: Volker Schwaberow <volker@schwaberow.de>
// Copyright (c) 2022 Volker Schwaberow

use crate::config::PasswordGeneratorConfig;
use rand::seq::SliceRandom;

pub async fn generate_password(config: &PasswordGeneratorConfig) -> String {
    let mut rng = rand::thread_rng();
    let mut password = String::with_capacity(config.length);

    let mut available_chars: Vec<char> = config.allowed_chars.clone();
    available_chars.extend(config.included_chars.iter());
    available_chars.retain(|c| !config.excluded_chars.contains(c));

    for _ in 0..config.length {
        if let Some(&ch) = available_chars.choose(&mut rng) {
            password.push(ch);
            if config.avoid_repetition {
                let mut seen = std::collections::HashSet::new();
                available_chars.retain(|&c| {
                    if seen.contains(&c) {
                        false
                    } else {
                        seen.insert(c);
                        true
                    }
                });
            }
        }
    }

    password
}

pub async fn generate_passwords(config: &PasswordGeneratorConfig) -> Vec<String> {
    let mut passwords = Vec::with_capacity(config.num_passwords);
    for _ in 0..config.num_passwords {
        passwords.push(generate_password(config).await);
    }
    passwords
}

pub async fn generate_diceware_passphrase(
    wordlist: &[String],
    config: &PasswordGeneratorConfig,
) -> Vec<String> {
    let mut rng = rand::thread_rng();
    let num_passphrases = config.num_passwords;
    let mut passphrases = Vec::with_capacity(num_passphrases);
    let num_words = config.length;

    for _ in 0..num_passphrases {
        let passphrase: String = (0..num_words)
            .map(|i| {
                let word = wordlist.choose(&mut rng).unwrap();
                if i > 0 {
                    format!(" {}", word)
                } else {
                    word.clone()
                }
            })
            .collect();
        passphrases.push(passphrase);
    }

    passphrases
}
