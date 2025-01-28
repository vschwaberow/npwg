// SPDX-License-Identifier: MIT
// Project: npwg
// File: src/generator.rs
// Author: Volker Schwaberow <volker@schwaberow.de>
// Copyright (c) 2022 Volker Schwaberow

use crate::config::PasswordGeneratorConfig;
use crate::config::Separator;
use clap::ValueEnum;
use rand::seq::IndexedRandom;
use rand::seq::IteratorRandom;
use rand::Rng;

const DEFAULT_SEPARATORS: &[char] = &[
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's',
    't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
];

#[derive(Debug, ValueEnum, Clone)]
pub enum MutationType {
    Replace,
    Insert,
    Remove,
    Swap,
    Shift,
}

impl std::fmt::Display for MutationType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MutationType::Replace => write!(f, "replace"),
            MutationType::Insert => write!(f, "insert"),
            MutationType::Remove => write!(f, "remove"),
            MutationType::Swap => write!(f, "swap"),
            MutationType::Shift => write!(f, "shift"),
        }
    }
}

impl std::str::FromStr for MutationType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "replace" => Ok(MutationType::Replace),
            "insert" => Ok(MutationType::Insert),
            "remove" => Ok(MutationType::Remove),
            "swap" => Ok(MutationType::Swap),
            "shift" => Ok(MutationType::Shift),
            _ => Err(format!("Invalid mutation type: {}", s)),
        }
    }
}

pub async fn generate_password(config: &PasswordGeneratorConfig) -> String {
    let mut rng = rand::rng();
    let mut password = String::with_capacity(config.length);

    let mut available_chars: Vec<char> = config.allowed_chars.clone();
    available_chars.extend(config.included_chars.iter());
    available_chars.retain(|c| !config.excluded_chars.contains(c));

    if let Some(pattern) = &config.pattern {
        return generate_with_pattern(pattern, &available_chars, config.length);
    }

    for _ in 0..config.length {
        if let Some(&c) = available_chars.choose(&mut rng) {
            password.push(c);
        }
    }

    password
}

fn generate_with_pattern(pattern: &str, available_chars: &[char], length: usize) -> String {
    let mut rng = rand::rng();
    let mut password = String::with_capacity(length);

    for symbol in pattern.chars() {
        let char_opt = match symbol {
            'L' | 'l' => available_chars.iter().filter(|c| c.is_ascii_alphabetic()).choose(&mut rng),
            'D' | 'd' => available_chars.iter().filter(|c| c.is_ascii_digit()).choose(&mut rng),
            'S' | 's' => available_chars.iter().filter(|c| !c.is_ascii_alphanumeric()).choose(&mut rng),
            _ => None,
        };

        if let Some(&c) = char_opt {
            password.push(c);
        } else {
            password.push(symbol);
        }
    }

    while password.len() < length {
        if let Some(&c) = available_chars.choose(&mut rng) {
            password.push(c);
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

pub fn mutate_password(
    password: &str,
    config: &PasswordGeneratorConfig,
    lengthen: usize,
    mutation_strength: u32,
) -> String {
    let mut rng = rand::thread_rng();
    let mut mutated = password.to_string();
    let mutation_count =
        (password.len() as f64 * (mutation_strength as f64 / 10.0)).ceil() as usize;

    for _ in 0..mutation_count {
        let index = rng.gen_range(0..mutated.len());
        let mutation_type = match rng.gen_range(0..4) {
            0 => MutationType::Replace,
            1 => MutationType::Insert,
            2 => MutationType::Remove,
            3 => MutationType::Swap,
            _ => unreachable!(),
        };

        match mutation_type {
            MutationType::Replace => {
                if let Some(new_char) = config.allowed_chars.choose(&mut rng) {
                    mutated.replace_range(index..index + 1, &new_char.to_string());
                }
            }
            MutationType::Insert => {
                if let Some(new_char) = config.allowed_chars.choose(&mut rng) {
                    mutated.insert(index, *new_char);
                }
            }
            MutationType::Remove => {
                if mutated.len() > 1 {
                    mutated.remove(index);
                }
            }
            MutationType::Swap => {
                if index < mutated.len() - 1 {
                    let mut chars: Vec<char> = mutated.chars().collect();
                    chars.swap(index, index + 1);
                    mutated = chars.into_iter().collect();
                }
            }
            MutationType::Shift => {
                let shift_factor = rng.gen_range(1..50);
                mutated = shift_and_encode(&mutated, shift_factor);
            }
        }
    }

    if lengthen > 0 {
        mutated = lengthen_password(&mutated, lengthen);
    }

    mutated
}

fn shift_and_encode(password: &str, shift: u8) -> String {
    password
        .chars()
        .map(|c| {
            let shifted = (c as u8).wrapping_add(shift);
            (shifted % 95 + 32) as char
        })
        .collect()
}

fn lengthen_password(password: &str, increase: usize) -> String {
    let mut lengthened = password.to_string();
    for _ in 0..increase {
        lengthened.push(random_char());
    }
    lengthened
}

fn random_char() -> char {
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()"
        .chars()
        .collect::<Vec<char>>()
        .choose(&mut rand::thread_rng())
        .copied()
        .unwrap()
}
