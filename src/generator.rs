// SPDX-License-Identifier: MIT
// Project: npwg
// File: src/generator.rs
// Author: Volker Schwaberow <volker@schwaberow.de>
// Copyright (c) 2022 Volker Schwaberow

use crate::config::PasswordGeneratorConfig;
use crate::config::Separator;
use rand::seq::SliceRandom;
use rand::Rng;

const DEFAULT_SEPARATORS: &[char] = &[
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's',
    't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
];

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
    let num_words = config.length;
    let mut passphrases = Vec::with_capacity(num_passphrases);

    for _ in 0..num_passphrases {
        let mut passphrase = String::with_capacity(num_words * 5 + (num_words - 1));
        for i in 0..num_words {
            if i > 0 {
                passphrase.push_str(&get_separator(config, DEFAULT_SEPARATORS, &mut rng));
            }
            passphrase.push_str(wordlist.choose(&mut rng).unwrap());
        }
        passphrases.push(passphrase);
    }

    passphrases
}

fn get_separator(
    config: &PasswordGeneratorConfig,
    default_separators: &[char],
    rng: &mut impl rand::Rng,
) -> String {
    match &config.separator {
        Some(Separator::Fixed(c)) => c.to_string(),
        Some(Separator::Random(chars)) => chars.choose(rng).unwrap().to_string(),
        None => default_separators.choose(rng).unwrap().to_string(),
    }
}

pub async fn generate_pronounceable_password(config: &PasswordGeneratorConfig) -> String {
    let mut rng = rand::thread_rng();
    let mut password = String::with_capacity(config.length);

    let consonants = "bcdfghjklmnpqrstvwxyz";
    let vowels = "aeiou";

    while password.len() < config.length {
        if password.len() % 2 == 0 {
            password.push(
                *consonants
                    .chars()
                    .collect::<Vec<char>>()
                    .choose(&mut rng)
                    .unwrap(),
            );
        } else {
            password.push(
                *vowels
                    .chars()
                    .collect::<Vec<char>>()
                    .choose(&mut rng)
                    .unwrap(),
            );
        }
    }

    password
}

pub async fn generate_pronounceable_passwords(config: &PasswordGeneratorConfig) -> Vec<String> {
    let mut passwords = Vec::with_capacity(config.num_passwords);
    for _ in 0..config.num_passwords {
        passwords.push(generate_pronounceable_password(config).await);
    }
    passwords
}

pub fn mutate_password(password: &str, config: &PasswordGeneratorConfig) -> String {
    let mut rng = rand::thread_rng();
    let mut mutated = password.to_string();
    let mutation_count = (password.len() as f64 * 0.2).ceil() as usize;

    for _ in 0..mutation_count {
        let index = rng.gen_range(0..mutated.len());
        let mutation_type = rng.gen_range(0..4);

        match mutation_type {
            0 => {
                if let Some(new_char) = config.allowed_chars.choose(&mut rng) {
                    mutated.replace_range(index..index + 1, &new_char.to_string());
                }
            }
            1 => {
                if let Some(new_char) = config.allowed_chars.choose(&mut rng) {
                    mutated.insert(index, *new_char);
                }
            }
            2 => {
                if mutated.len() > 1 {
                    mutated.remove(index);
                }
            }
            3 => {
                if index < mutated.len() - 1 {
                    let mut chars: Vec<char> = mutated.chars().collect();
                    chars.swap(index, index + 1);
                    mutated = chars.into_iter().collect();
                }
            }
            _ => unreachable!(),
        }
    }

    mutated
}
