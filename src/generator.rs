// SPDX-License-Identifier: MIT
// Project: npwg
// File: src/generator.rs
// Author: Volker Schwaberow <volker@schwaberow.de>
// Copyright (c) 2022 Volker Schwaberow

use crate::config::PasswordGeneratorConfig;
use crate::config::Separator;
use crate::error::{PasswordGeneratorError, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use clap::ValueEnum;
use rand::rngs::StdRng;
use rand::seq::IndexedRandom;
use rand::seq::IteratorRandom;
use rand::{Rng, SeedableRng};
use std::collections::HashSet;
use zeroize::Zeroize;

const DEFAULT_SEPARATORS: &[char] = &[
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's',
    't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
];

const ARGON2_M_COST_KIB: u32 = 64 * 1024;
const ARGON2_T_COST: u32 = 3;
const ARGON2_P_COST: u32 = 1;
const DETERMINISTIC_BLOCK_LEN: usize = 64;

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

    fn from_str(s: &str) -> std::result::Result<MutationType, std::string::String> {
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

pub async fn generate_password(config: &PasswordGeneratorConfig) -> Result<String> {
    let mut rng = match config.seed {
        Some(seed) => StdRng::seed_from_u64(seed),
        None => StdRng::from_rng(&mut rand::rng()),
    };
    let mut password = String::with_capacity(config.length);

    let available_chars = effective_allowed_chars(config)?;

    if let Some(pattern) = &config.pattern {
        return generate_with_pattern(pattern, &available_chars, config.length, config.seed);
    }

    for _ in 0..config.length {
        if let Some(&c) = available_chars.choose(&mut rng) {
            password.push(c);
        }
    }

    Ok(password)
}

pub fn generate_deterministic_password(
    master_password: &str,
    service: &str,
    username: Option<&str>,
    counter: u32,
    length: usize,
    allowed_chars: &[char],
) -> Result<String> {
    if allowed_chars.is_empty() {
        return Err(PasswordGeneratorError::InvalidConfig(
            "No characters available for deterministic generation.".to_string(),
        ));
    }

    let mut output = String::with_capacity(length);
    let mut block_index: u32 = 0;

    while output.len() < length {
        let salt = build_salt(service, username, counter, block_index);
        let mut block = derive_argon2_block(
            master_password.as_bytes(),
            salt.as_bytes(),
            DETERMINISTIC_BLOCK_LEN,
        )?;
        append_mapped_chars(&block, allowed_chars, length, &mut output);
        block.zeroize();
        block_index = block_index
            .checked_add(1)
            .ok_or_else(|| PasswordGeneratorError::InvalidConfig("Counter overflow.".to_string()))?;
    }

    Ok(output)
}

pub fn generate_with_pattern(
    pattern: &str,
    available_chars: &[char],
    length: usize,
    seed: Option<u64>,
) -> Result<String> {
    if available_chars.is_empty() {
        return Err(PasswordGeneratorError::InvalidConfig(
            "No characters available for generation with the current settings.".to_string(),
        ));
    }

    let mut rng = match seed {
        Some(seed) => StdRng::seed_from_u64(seed),
        None => StdRng::from_rng(&mut rand::rng()),
    };
    let mut password = String::with_capacity(length);

    for symbol in pattern.chars() {
        let char_opt = match symbol {
            'L' | 'l' => available_chars
                .iter()
                .filter(|c| c.is_ascii_alphabetic())
                .choose(&mut rng),
            'D' | 'd' => available_chars
                .iter()
                .filter(|c| c.is_ascii_digit())
                .choose(&mut rng),
            'S' | 's' => available_chars
                .iter()
                .filter(|c| !c.is_ascii_alphanumeric())
                .choose(&mut rng),
            _ => None,
        };

        if let Some(&c) = char_opt {
            password.push(c);
        }
    }

    while password.len() < length {
        if let Some(&c) = available_chars.choose(&mut rng) {
            password.push(c);
        }
    }

    Ok(password)
}

pub async fn generate_passwords(config: &PasswordGeneratorConfig) -> Result<Vec<String>> {
    let mut passwords = Vec::with_capacity(config.num_passwords);
    for _ in 0..config.num_passwords {
        passwords.push(generate_password(config).await?);
    }
    Ok(passwords)
}

pub async fn generate_diceware_passphrase(
    wordlist: &[String],
    config: &PasswordGeneratorConfig,
) -> Result<Vec<String>> {
    if wordlist.is_empty() {
        return Err(PasswordGeneratorError::InvalidConfig(
            "Cannot generate diceware passphrase: wordlist is empty.".to_string(),
        ));
    }

    let mut rng = match config.seed {
        Some(seed) => StdRng::seed_from_u64(seed),
        None => StdRng::from_rng(&mut rand::rng()),
    };
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

    Ok(passphrases)
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

pub async fn generate_pronounceable_password(config: &PasswordGeneratorConfig) -> Result<String> {
    let mut rng = match config.seed {
        Some(seed) => StdRng::seed_from_u64(seed),
        None => StdRng::from_rng(&mut rand::rng()),
    };
    let mut password = String::with_capacity(config.length);

    let consonants = "bcdfghjklmnpqrstvwxyz";
    let vowels = "aeiou";

    if consonants.is_empty() || vowels.is_empty() {
        return Err(PasswordGeneratorError::InvalidConfig(
            "Cannot generate pronounceable password: character sets are empty.".to_string(),
        ));
    }

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

    Ok(password)
}

pub async fn generate_pronounceable_passwords(
    config: &PasswordGeneratorConfig,
) -> Result<Vec<String>> {
    let mut passwords = Vec::with_capacity(config.num_passwords);
    for _ in 0..config.num_passwords {
        passwords.push(generate_pronounceable_password(config).await?);
    }
    Ok(passwords)
}

pub fn mutate_password(
    password: &str,
    config: &PasswordGeneratorConfig,
    lengthen: usize,
    mutation_strength: u32,
    forced_mutation_type: Option<&MutationType>,
) -> String {
    if password.is_empty() {
        return String::new();
    }

    let mut rng = match config.seed {
        Some(seed) => StdRng::seed_from_u64(seed),
        None => StdRng::from_rng(&mut rand::rng()),
    };
    let mut mutated = password.to_string();
    let mutation_count = mutation_strength.min(mutated.len() as u32);

    for _ in 0..mutation_count {
        if mutated.is_empty() {
            break;
        }

        let current_mutation_type = match forced_mutation_type {
            Some(t) => t.clone(),
            None => match rng.random_range(0..5) {
                0 => MutationType::Replace,
                1 => MutationType::Insert,
                2 => MutationType::Remove,
                3 => MutationType::Swap,
                4 => MutationType::Shift,
                _ => unreachable!(),
            },
        };
        let index = if mutated.is_empty() {
            0
        } else {
            rng.random_range(0..mutated.len())
        };

        match current_mutation_type {
            MutationType::Replace => {
                if !mutated.is_empty() {
                    let char_to_replace = mutated.chars().nth(index).unwrap();
                    let new_char = config
                        .allowed_chars
                        .iter()
                        .filter(|&&c| c != char_to_replace)
                        .choose(&mut rng)
                        .copied()
                        .unwrap_or(char_to_replace);
                    mutated.replace_range(index..index + 1, &new_char.to_string());
                }
            }
            MutationType::Insert => {
                let new_char = config
                    .allowed_chars
                    .choose(&mut rng)
                    .copied()
                    .unwrap_or('a');
                mutated.insert(index, new_char);
            }
            MutationType::Remove => {
                if !mutated.is_empty() {
                    mutated.remove(index);
                }
            }
            MutationType::Swap => {
                if mutated.len() > 1 {
                    let index2 =
                        (index + 1 + rng.random_range(0..mutated.len() - 1)) % mutated.len();
                    if index != index2 {
                        let char1 = mutated.chars().nth(index).unwrap();
                        let char2 = mutated.chars().nth(index2).unwrap();
                        mutated.replace_range(index..index + 1, &char2.to_string());
                        mutated.replace_range(index2..index2 + 1, &char1.to_string());
                    }
                }
            }
            MutationType::Shift => {
                if mutated.len() > 1 {
                    let shift_amount = rng.random_range(1..mutated.len());
                    let (first, second) = mutated.split_at(shift_amount);
                    mutated = format!("{}{}", second, first);
                }
            }
        }
    }

    if lengthen > 0 {
        for _ in 0..lengthen {
            if let Some(&c) = config.allowed_chars.choose(&mut rng) {
                mutated.push(c);
            }
        }
    }

    mutated
}

pub fn effective_allowed_chars(config: &PasswordGeneratorConfig) -> Result<Vec<char>> {
    let mut available_chars: Vec<char> = config.allowed_chars.clone();
    let mut included_chars: Vec<char> = config.included_chars.iter().copied().collect();
    included_chars.sort_unstable();
    available_chars.extend(included_chars);
    available_chars.retain(|c| !config.excluded_chars.contains(c));
    let mut seen = HashSet::new();
    available_chars.retain(|c| seen.insert(*c));
    if available_chars.is_empty() {
        return Err(PasswordGeneratorError::InvalidConfig(
            "No characters available for generation with the current settings.".to_string(),
        ));
    }
    Ok(available_chars)
}

fn build_salt(service: &str, username: Option<&str>, counter: u32, block_index: u32) -> String {
    match username {
        Some(username) => format!("npwg:{}:{}:{}:{}", service, username, counter, block_index),
        None => format!("npwg:{}:{}:{}", service, counter, block_index),
    }
}

fn derive_argon2_block(
    password: &[u8],
    salt: &[u8],
    output_len: usize,
) -> Result<Vec<u8>> {
    let params = Params::new(ARGON2_M_COST_KIB, ARGON2_T_COST, ARGON2_P_COST, Some(output_len))
        .map_err(|e| PasswordGeneratorError::KdfError(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut output = vec![0u8; output_len];
    argon2
        .hash_password_into(password, salt, &mut output)
        .map_err(|e| PasswordGeneratorError::KdfError(e.to_string()))?;
    Ok(output)
}

fn append_mapped_chars(
    bytes: &[u8],
    alphabet: &[char],
    target_len: usize,
    output: &mut String,
) {
    let alphabet_len = alphabet.len();
    if alphabet_len == 0 {
        return;
    }
    let threshold = (u8::MAX as usize + 1) / alphabet_len * alphabet_len;

    for &byte in bytes {
        if output.len() >= target_len {
            break;
        }
        let value = byte as usize;
        if value < threshold {
            output.push(alphabet[value % alphabet_len]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_with_pattern_skip_unfulfillable_chars() {
        let available_chars: Vec<char> = "abcdefg".chars().collect();
        let pattern = "LDLS";
        let length = 10;
        let seed = None;

        let result = generate_with_pattern(pattern, &available_chars, length, seed);
        assert!(
            result.is_ok(),
            "Expected successful generation despite unfulfillable pattern"
        );

        let password = result.unwrap();
        assert_eq!(
            password.len(),
            length,
            "Password should match the requested length"
        );

        for c in password.chars() {
            assert!(
                available_chars.contains(&c),
                "Password contains character not in available_chars: {}",
                c
            );
        }
        assert!(
            !password.chars().any(|c| c.is_ascii_digit()),
            "Password should not contain digits"
        );
    }

    #[test]
    fn test_generate_deterministic_password_is_stable() {
        let allowed_chars: Vec<char> = "abc123!@#".chars().collect();
        let first = generate_deterministic_password(
            "master-password",
            "example.com",
            Some("alice"),
            1,
            24,
            &allowed_chars,
        )
        .unwrap();
        let second = generate_deterministic_password(
            "master-password",
            "example.com",
            Some("alice"),
            1,
            24,
            &allowed_chars,
        )
        .unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn test_generate_deterministic_password_changes_with_service() {
        let allowed_chars: Vec<char> = "abc123!@#".chars().collect();
        let first = generate_deterministic_password(
            "master-password",
            "example.com",
            Some("alice"),
            1,
            24,
            &allowed_chars,
        )
        .unwrap();
        let second = generate_deterministic_password(
            "master-password",
            "example.net",
            Some("alice"),
            1,
            24,
            &allowed_chars,
        )
        .unwrap();
        assert_ne!(first, second);
    }
}
