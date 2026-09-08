// SPDX-License-Identifier: MIT
// Project: npwg
// File: src/generator.rs
// Author: Volker Schwaberow <volker@schwaberow.de>
// Copyright (c) 2022 Volker Schwaberow

use crate::config::PasswordGeneratorConfig;
use crate::config::PasswordGeneratorMode;
use crate::config::RequireClass;
use crate::config::Separator;
use crate::config::DEFINE;
use crate::error::{PasswordGeneratorError, Result};
use crate::strength::{charset_probe, estimate_entropy_bits, max_entropy_bits_for_probe};
use argon2::{Algorithm, Argon2, Params, Version};
use clap::ValueEnum;
use rand::rngs::StdRng;
use rand::seq::IndexedRandom;
use rand::seq::IteratorRandom;
use rand::{RngExt, SeedableRng};
use std::collections::HashSet;
use zeroize::Zeroize;

const MIN_ENTROPY_MAX_ATTEMPTS: usize = 10_000;

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
        return generate_with_pattern(
            pattern,
            &available_chars,
            config.length,
            config.seed,
            config.avoid_repetition,
        );
    }

    let mut last: Option<char> = None;
    for _ in 0..config.length {
        if let Some(c) = choose_char(&available_chars, &mut rng, last, config.avoid_repetition) {
            password.push(c);
            last = Some(c);
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
        block_index = block_index.checked_add(1).ok_or_else(|| {
            PasswordGeneratorError::InvalidConfig("Counter overflow.".to_string())
        })?;
    }

    Ok(output)
}

fn pattern_pool(symbol: char, available_chars: &[char]) -> Result<Vec<char>> {
    let pool: Vec<char> = match symbol {
        'L' | 'l' => available_chars
            .iter()
            .copied()
            .filter(|c| c.is_ascii_alphabetic())
            .collect(),
        'D' | 'd' => available_chars
            .iter()
            .copied()
            .filter(|c| c.is_ascii_digit())
            .collect(),
        'S' | 's' => available_chars
            .iter()
            .copied()
            .filter(|c| !c.is_ascii_alphanumeric())
            .collect(),
        _ => {
            return Err(PasswordGeneratorError::InvalidConfig(format!(
                "Invalid pattern symbol '{}'. Use L, D, or S.",
                symbol
            )));
        }
    };
    if pool.is_empty() {
        return Err(PasswordGeneratorError::InvalidConfig(format!(
            "Pattern symbol '{}' cannot be satisfied with the current allowed characters.",
            symbol
        )));
    }
    Ok(pool)
}

pub fn generate_with_pattern(
    pattern: &str,
    available_chars: &[char],
    length: usize,
    seed: Option<u64>,
    avoid_repetition: bool,
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
    let mut last: Option<char> = None;

    for symbol in pattern.chars() {
        let pool = pattern_pool(symbol, available_chars)?;
        if let Some(c) = choose_char(&pool, &mut rng, last, avoid_repetition) {
            password.push(c);
            last = Some(c);
        }
    }

    let pattern_len = password.chars().count();
    if pattern_len > length {
        return Err(PasswordGeneratorError::InvalidConfig(format!(
            "Pattern produces {} characters, which exceeds the requested length of {}.",
            pattern_len, length
        )));
    }

    while password.chars().count() < length {
        if let Some(c) = choose_char(available_chars, &mut rng, last, avoid_repetition) {
            password.push(c);
            last = Some(c);
        } else {
            return Err(PasswordGeneratorError::InvalidConfig(
                "Could not fill password to the requested length with the current settings."
                    .to_string(),
            ));
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

pub fn ensure_min_entropy_feasible(
    config: &PasswordGeneratorConfig,
    min_bits: f64,
    wordlist_len: Option<usize>,
) -> Result<()> {
    if min_bits <= 0.0 {
        return Err(PasswordGeneratorError::InvalidConfig(
            "--min-entropy must be greater than 0.".to_string(),
        ));
    }

    let max_bits = match config.mode {
        PasswordGeneratorMode::Diceware => {
            let size = wordlist_len.ok_or_else(|| {
                PasswordGeneratorError::InvalidConfig(
                    "Diceware --min-entropy requires a loaded wordlist.".to_string(),
                )
            })? as f64;
            if size <= 1.0 {
                return Err(PasswordGeneratorError::InvalidConfig(
                    "Wordlist is too small to estimate entropy.".to_string(),
                ));
            }
            config.length as f64 * size.log2()
        }
        PasswordGeneratorMode::Password => {
            let allowed = effective_allowed_chars(config)?;
            let probe = charset_probe(&allowed);
            max_entropy_bits_for_probe(config.length, &probe)
        }
    };

    if max_bits + 1e-9 < min_bits {
        return Err(PasswordGeneratorError::InvalidConfig(format!(
            "Requested --min-entropy {:.1} bits exceeds the maximum ≈ {:.1} bits for length {} with the current settings.",
            min_bits, max_bits, config.length
        )));
    }
    Ok(())
}

pub async fn generate_password_with_min_entropy(
    config: &PasswordGeneratorConfig,
    min_bits: f64,
) -> Result<String> {
    ensure_min_entropy_feasible(config, min_bits, None)?;
    for _ in 0..MIN_ENTROPY_MAX_ATTEMPTS {
        let mut password = if config.pronounceable {
            generate_pronounceable_password(config).await?
        } else {
            generate_password(config).await?
        };
        if estimate_entropy_bits(&password) >= min_bits {
            return Ok(password);
        }
        password.zeroize();
    }
    Err(PasswordGeneratorError::InvalidConfig(format!(
        "Could not reach --min-entropy {:.1} bits within {} attempts.",
        min_bits, MIN_ENTROPY_MAX_ATTEMPTS
    )))
}

pub async fn generate_passwords_with_min_entropy(
    config: &PasswordGeneratorConfig,
    min_bits: f64,
) -> Result<Vec<String>> {
    ensure_min_entropy_feasible(config, min_bits, None)?;
    let mut passwords = Vec::with_capacity(config.num_passwords);
    for _ in 0..config.num_passwords {
        passwords.push(generate_password_with_min_entropy(config, min_bits).await?);
    }
    Ok(passwords)
}

pub async fn generate_diceware_passphrase_with_min_entropy(
    wordlist: &[String],
    config: &PasswordGeneratorConfig,
    min_bits: f64,
) -> Result<Vec<String>> {
    ensure_min_entropy_feasible(config, min_bits, Some(wordlist.len()))?;
    generate_diceware_passphrase(wordlist, config).await
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
                passphrase.push_str(&get_separator(config, DEFAULT_SEPARATORS, &mut rng)?);
            }
            let word = wordlist.choose(&mut rng).ok_or_else(|| {
                PasswordGeneratorError::InvalidConfig(
                    "Cannot choose a diceware word from an empty wordlist.".to_string(),
                )
            })?;
            passphrase.push_str(word);
        }
        append_required_classes(&mut passphrase, &config.require_classes, &mut rng)?;
        passphrases.push(passphrase);
    }

    Ok(passphrases)
}

fn require_class_pool(class: RequireClass) -> Result<&'static str> {
    let name = match class {
        RequireClass::Digit => "digit",
        RequireClass::Symbol => "symbol2",
    };
    DEFINE
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, chars)| *chars)
        .ok_or_else(|| {
            PasswordGeneratorError::InvalidConfig(format!("Missing charset '{}'.", name))
        })
}

fn append_required_classes(
    passphrase: &mut String,
    classes: &[RequireClass],
    rng: &mut impl RngExt,
) -> Result<()> {
    for class in classes {
        let pool = require_class_pool(*class)?;
        let chars: Vec<char> = pool.chars().collect();
        let c = chars.choose(rng).copied().ok_or_else(|| {
            PasswordGeneratorError::InvalidConfig(format!(
                "Empty character pool for --require {:?}.",
                class
            ))
        })?;
        passphrase.push(c);
    }
    Ok(())
}

fn get_separator(
    config: &PasswordGeneratorConfig,
    default_separators: &[char],
    rng: &mut impl rand::RngExt,
) -> Result<String> {
    match &config.separator {
        Some(Separator::Fixed(c)) => Ok(c.to_string()),
        Some(Separator::Random(chars)) => {
            chars.choose(rng).map(|c| c.to_string()).ok_or_else(|| {
                PasswordGeneratorError::InvalidConfig(
                    "Random separator character set is empty.".to_string(),
                )
            })
        }
        None => default_separators
            .choose(rng)
            .map(|c| c.to_string())
            .ok_or_else(|| {
                PasswordGeneratorError::InvalidConfig(
                    "Default separator character set is empty.".to_string(),
                )
            }),
    }
}

const PRONOUNCEABLE_VOWELS: &str = "aeiou";

pub async fn generate_pronounceable_password(config: &PasswordGeneratorConfig) -> Result<String> {
    let mut rng = match config.seed {
        Some(seed) => StdRng::seed_from_u64(seed),
        None => StdRng::from_rng(&mut rand::rng()),
    };
    let available = effective_allowed_chars(config)?;
    let vowels: Vec<char> = available
        .iter()
        .copied()
        .filter(|c| PRONOUNCEABLE_VOWELS.contains(*c))
        .collect();
    let consonants: Vec<char> = available
        .iter()
        .copied()
        .filter(|c| c.is_ascii_alphabetic() && !PRONOUNCEABLE_VOWELS.contains(*c))
        .collect();

    if vowels.is_empty() || consonants.is_empty() {
        return Err(PasswordGeneratorError::InvalidConfig(
            "Cannot generate pronounceable password: allowed characters must include both vowels and consonants.".to_string(),
        ));
    }

    let mut password = String::with_capacity(config.length);
    while password.chars().count() < config.length {
        let pool = if password.chars().count().is_multiple_of(2) {
            &consonants
        } else {
            &vowels
        };
        if let Some(&c) = pool.choose(&mut rng) {
            password.push(c);
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
) -> Result<String> {
    if password.is_empty() {
        return Err(PasswordGeneratorError::InvalidConfig(
            "Cannot mutate an empty password.".to_string(),
        ));
    }

    let allowed_chars = effective_allowed_chars(config)?;

    let mut rng = match config.seed {
        Some(seed) => StdRng::seed_from_u64(seed),
        None => StdRng::from_rng(&mut rand::rng()),
    };
    let mut mutated = password.to_string();
    let mutation_count = mutation_strength.min(mutated.chars().count() as u32);

    for _ in 0..mutation_count {
        let char_len = mutated.chars().count();
        if char_len == 0 {
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
        let index = rng.random_range(0..char_len);

        match current_mutation_type {
            MutationType::Replace => {
                if let Some((start, end)) = char_byte_range(&mutated, index) {
                    let char_to_replace = mutated[start..end].chars().next().unwrap();
                    let new_char = allowed_chars
                        .iter()
                        .filter(|&&c| c != char_to_replace)
                        .choose(&mut rng)
                        .copied()
                        .unwrap_or(char_to_replace);
                    mutated.replace_range(start..end, &new_char.to_string());
                }
            }
            MutationType::Insert => {
                let new_char = allowed_chars.choose(&mut rng).copied().ok_or_else(|| {
                    PasswordGeneratorError::InvalidConfig(
                        "Cannot insert a character: allowed character set is empty.".to_string(),
                    )
                })?;
                if let Some((start, _)) = char_byte_range(&mutated, index) {
                    mutated.insert(start, new_char);
                } else {
                    mutated.push(new_char);
                }
            }
            MutationType::Remove => {
                if let Some((start, end)) = char_byte_range(&mutated, index) {
                    mutated.replace_range(start..end, "");
                }
            }
            MutationType::Swap => {
                if char_len > 1 {
                    let index2 = (index + 1 + rng.random_range(0..char_len - 1)) % char_len;
                    if index != index2 {
                        let mut chars: Vec<char> = mutated.chars().collect();
                        chars.swap(index, index2);
                        mutated = chars.into_iter().collect();
                    }
                }
            }
            MutationType::Shift => {
                if char_len > 1 {
                    let shift_amount = rng.random_range(1..char_len);
                    if let Some((byte_idx, _)) = char_byte_range(&mutated, shift_amount) {
                        let (first, second) = mutated.split_at(byte_idx);
                        mutated = format!("{}{}", second, first);
                    }
                }
            }
        }
    }

    if lengthen > 0 {
        for _ in 0..lengthen {
            if let Some(&c) = allowed_chars.choose(&mut rng) {
                mutated.push(c);
            }
        }
    }

    Ok(mutated)
}

fn choose_char(
    chars: &[char],
    rng: &mut impl RngExt,
    last: Option<char>,
    avoid_repetition: bool,
) -> Option<char> {
    if chars.is_empty() {
        return None;
    }
    if avoid_repetition {
        if let Some(last) = last {
            let alternatives: Vec<char> = chars.iter().copied().filter(|&c| c != last).collect();
            if !alternatives.is_empty() {
                return alternatives.choose(rng).copied();
            }
        }
    }
    chars.choose(rng).copied()
}

fn char_byte_range(s: &str, char_index: usize) -> Option<(usize, usize)> {
    let mut indices = s.char_indices();
    let (start, _) = indices.nth(char_index)?;
    let end = indices.next().map(|(i, _)| i).unwrap_or(s.len());
    Some((start, end))
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

fn derive_argon2_block(password: &[u8], salt: &[u8], output_len: usize) -> Result<Vec<u8>> {
    let params = Params::new(
        ARGON2_M_COST_KIB,
        ARGON2_T_COST,
        ARGON2_P_COST,
        Some(output_len),
    )
    .map_err(|e| PasswordGeneratorError::KdfError(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut output = vec![0u8; output_len];
    argon2
        .hash_password_into(password, salt, &mut output)
        .map_err(|e| PasswordGeneratorError::KdfError(e.to_string()))?;
    Ok(output)
}

fn append_mapped_chars(bytes: &[u8], alphabet: &[char], target_len: usize, output: &mut String) {
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
    use crate::strength::estimate_entropy_bits;

    #[test]
    fn test_generate_with_pattern_rejects_pattern_longer_than_length() {
        let available_chars: Vec<char> = "abc123!".chars().collect();
        let result = generate_with_pattern("LLLLLLLLLL", &available_chars, 8, None, false);
        assert!(result.is_err());
    }

    #[test]
    fn test_generate_with_pattern_rejects_unfulfillable_symbols() {
        let available_chars: Vec<char> = "abcdefg".chars().collect();
        let pattern = "LDLS";
        let length = 10;
        let seed = None;

        let result = generate_with_pattern(pattern, &available_chars, length, seed, false);
        assert!(result.is_err());
    }

    #[test]
    fn test_generate_with_pattern_succeeds_when_satisfiable() {
        let available_chars: Vec<char> = "abc123!".chars().collect();
        let pattern = "LLDDS";
        let length = 8;
        let seed = Some(42);

        let password =
            generate_with_pattern(pattern, &available_chars, length, seed, false).unwrap();
        assert_eq!(password.chars().count(), length);
        for c in password.chars() {
            assert!(available_chars.contains(&c));
        }
    }

    #[tokio::test]
    async fn test_pronounceable_respects_allowed_chars() {
        let mut config = PasswordGeneratorConfig::new();
        config.clear_allowed_chars();
        config.allowed_chars = "0123456789".chars().collect();
        config.length = 8;
        let err = generate_pronounceable_password(&config).await.unwrap_err();
        assert!(matches!(err, PasswordGeneratorError::InvalidConfig(_)));
    }

    #[tokio::test]
    async fn test_pronounceable_uses_allowed_letters_only() {
        let mut config = PasswordGeneratorConfig::new();
        config.clear_allowed_chars();
        config.allowed_chars = "aeib".chars().collect();
        config.length = 6;
        config.seed = Some(1);
        let password = generate_pronounceable_password(&config).await.unwrap();
        assert!(password.chars().all(|c| "aeib".contains(c)));
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

    #[tokio::test]
    async fn test_avoid_repetition_with_seed() {
        let mut config = PasswordGeneratorConfig::new();
        config.clear_allowed_chars();
        config.allowed_chars = vec!['a', 'b'];
        config.length = 20;
        config.seed = Some(42);
        config.avoid_repetition = true;
        let password = generate_password(&config).await.unwrap();
        let chars: Vec<char> = password.chars().collect();
        assert!(chars.windows(2).all(|w| w[0] != w[1]));
    }

    #[test]
    fn test_mutate_password_handles_unicode() {
        let mut config = PasswordGeneratorConfig::new();
        config.seed = Some(7);
        let mutated = mutate_password("äöüß", &config, 0, 3, Some(&MutationType::Swap)).unwrap();
        assert_eq!(mutated.chars().count(), 4);
    }

    #[test]
    fn test_mutate_password_rejects_empty_input() {
        let config = PasswordGeneratorConfig::new();
        let err = mutate_password("", &config, 0, 1, None).unwrap_err();
        assert!(matches!(err, PasswordGeneratorError::InvalidConfig(_)));
    }
    #[tokio::test]
    async fn test_min_entropy_rejects_impossible_threshold() {
        let mut config = PasswordGeneratorConfig::new();
        config.length = 8;
        config.clear_allowed_chars();
        config.allowed_chars = "0123456789".chars().collect();
        let err = generate_password_with_min_entropy(&config, 80.0)
            .await
            .unwrap_err();
        assert!(matches!(err, PasswordGeneratorError::InvalidConfig(_)));
    }

    #[tokio::test]
    async fn test_min_entropy_accepts_reachable_threshold() {
        let mut config = PasswordGeneratorConfig::new();
        config.length = 20;
        let password = generate_password_with_min_entropy(&config, 80.0)
            .await
            .unwrap();
        assert!(estimate_entropy_bits(&password) >= 80.0);
    }
    #[tokio::test]
    async fn test_diceware_require_appends_digit_and_symbol() {
        let wordlist = vec!["alpha".into(), "bravo".into(), "charlie".into()];
        let mut config = PasswordGeneratorConfig::new();
        config.set_use_words(true);
        config.length = 3;
        config.seed = Some(42);
        config.require_classes = vec![RequireClass::Digit, RequireClass::Symbol];
        let phrases = generate_diceware_passphrase(&wordlist, &config)
            .await
            .unwrap();
        assert_eq!(phrases.len(), 1);
        let phrase = &phrases[0];
        assert!(
            phrase.chars().any(|c| c.is_ascii_digit()),
            "missing digit in {phrase}"
        );
        assert!(
            phrase
                .chars()
                .any(|c| !c.is_ascii_alphanumeric() && c != ' '),
            "missing symbol in {phrase}"
        );
    }
}
