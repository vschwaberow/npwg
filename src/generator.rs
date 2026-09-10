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

#[derive(Debug, ValueEnum, Clone, Copy, PartialEq, Eq)]
pub enum DeterministicVersion {
    V1,
    V2,
}

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
    generate_password_with_wordlist(config, None).await
}

pub async fn generate_password_with_wordlist(
    config: &PasswordGeneratorConfig,
    wordlist_override: Option<&[String]>,
) -> Result<String> {
    let mut rng = match config.seed {
        Some(seed) => StdRng::seed_from_u64(seed),
        None => StdRng::from_rng(&mut rand::rng()),
    };
    let mut password = String::with_capacity(config.length);

    let available_chars = effective_allowed_chars(config)?;

    if let Some(pattern) = &config.pattern {
        let loaded_words;
        let wordlist = if let Some(words) = wordlist_override {
            Some(words)
        } else if pattern_needs_wordlist(pattern) {
            loaded_words =
                crate::diceware::get_wordlist(&crate::diceware::WordlistSource::default()).await?;
            Some(loaded_words.as_slice())
        } else {
            None
        };
        return generate_with_pattern(
            pattern,
            &available_chars,
            config.length,
            config.seed,
            config.avoid_repetition,
            wordlist,
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
    generate_deterministic_password_versioned(
        master_password,
        service,
        username,
        counter,
        length,
        allowed_chars,
        DeterministicVersion::V1,
    )
}

pub fn generate_deterministic_password_versioned(
    master_password: &str,
    service: &str,
    username: Option<&str>,
    counter: u32,
    length: usize,
    allowed_chars: &[char],
    version: DeterministicVersion,
) -> Result<String> {
    if allowed_chars.is_empty() {
        return Err(PasswordGeneratorError::InvalidConfig(
            "No characters available for deterministic generation.".to_string(),
        ));
    }
    let max_alphabet_len = match version {
        DeterministicVersion::V1 => 256,
        DeterministicVersion::V2 => u32::MAX as usize,
    };
    if allowed_chars.len() > max_alphabet_len {
        return Err(PasswordGeneratorError::InvalidConfig(format!(
            "The selected deterministic version supports at most {max_alphabet_len} alphabet entries."
        )));
    }

    let mut output = String::with_capacity(length);
    let mut block_index: u32 = 0;
    let mut produced_len = 0;

    while produced_len < length {
        let salt = match version {
            DeterministicVersion::V1 => {
                build_salt(service, username, counter, block_index).into_bytes()
            }
            DeterministicVersion::V2 => build_salt_v2(service, username, counter, block_index),
        };
        let mut block =
            derive_argon2_block(master_password.as_bytes(), &salt, DETERMINISTIC_BLOCK_LEN)?;
        match version {
            DeterministicVersion::V1 => {
                append_mapped_chars(&block, allowed_chars, length, &mut output);
                produced_len = output.len();
            }
            DeterministicVersion::V2 => {
                produced_len += append_mapped_chars_v2(
                    &block,
                    allowed_chars,
                    length - produced_len,
                    &mut output,
                );
            }
        }
        block.zeroize();
        if produced_len < length {
            block_index = block_index.checked_add(1).ok_or_else(|| {
                PasswordGeneratorError::InvalidConfig("Counter overflow.".to_string())
            })?;
        }
    }

    Ok(output)
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PatternToken {
    Class { symbol: char, count: usize },
    Word,
    Literal(char),
}

pub fn pattern_needs_wordlist(pattern: &str) -> bool {
    parse_pattern_tokens(pattern)
        .map(|tokens| tokens.iter().any(|t| matches!(t, PatternToken::Word)))
        .unwrap_or(false)
}

fn parse_pattern_tokens(pattern: &str) -> Result<Vec<PatternToken>> {
    let mut tokens = Vec::new();
    let mut chars = pattern.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '{' {
            let mut body = String::new();
            let mut closed = false;
            for inner in chars.by_ref() {
                if inner == '}' {
                    closed = true;
                    break;
                }
                body.push(inner);
            }
            if !closed {
                return Err(PasswordGeneratorError::InvalidConfig(
                    "Unclosed '{' in pattern.".to_string(),
                ));
            }
            let body = body.trim();
            if body.eq_ignore_ascii_case("word") {
                tokens.push(PatternToken::Word);
                continue;
            }
            let (symbol, count) = match body.split_once(':') {
                Some((sym, count_str)) => {
                    let sym = sym.trim();
                    if sym.len() != 1 {
                        return Err(PasswordGeneratorError::InvalidConfig(format!(
                            "Invalid pattern token '{{{}}}'.",
                            body
                        )));
                    }
                    let symbol = sym.chars().next().unwrap();
                    let count: usize = count_str.trim().parse().map_err(|_| {
                        PasswordGeneratorError::InvalidConfig(format!(
                            "Invalid pattern count in '{{{}}}'.",
                            body
                        ))
                    })?;
                    if count == 0 {
                        return Err(PasswordGeneratorError::InvalidConfig(
                            "Pattern class count must be greater than 0.".to_string(),
                        ));
                    }
                    (symbol, count)
                }
                None => {
                    return Err(PasswordGeneratorError::InvalidConfig(format!(
                        "Invalid pattern token '{{{}}}'. Use {{L:n}}, {{D:n}}, {{S:n}}, or {{word}}.",
                        body
                    )));
                }
            };
            match symbol {
                'L' | 'l' | 'D' | 'd' | 'S' | 's' => {
                    tokens.push(PatternToken::Class { symbol, count });
                }
                _ => {
                    return Err(PasswordGeneratorError::InvalidConfig(format!(
                        "Invalid pattern class '{}'. Use L, D, or S.",
                        symbol
                    )));
                }
            }
        } else if matches!(ch, 'L' | 'l' | 'D' | 'd' | 'S' | 's') {
            tokens.push(PatternToken::Class {
                symbol: ch,
                count: 1,
            });
        } else {
            tokens.push(PatternToken::Literal(ch));
        }
    }
    Ok(tokens)
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
    wordlist: Option<&[String]>,
) -> Result<String> {
    if available_chars.is_empty() {
        return Err(PasswordGeneratorError::InvalidConfig(
            "No characters available for generation with the current settings.".to_string(),
        ));
    }

    let tokens = parse_pattern_tokens(pattern)?;
    if tokens.iter().any(|t| matches!(t, PatternToken::Word)) && wordlist.is_none() {
        return Err(PasswordGeneratorError::InvalidConfig(
            "Pattern uses {word} but no wordlist is available.".to_string(),
        ));
    }

    let mut rng = match seed {
        Some(seed) => StdRng::seed_from_u64(seed),
        None => StdRng::from_rng(&mut rand::rng()),
    };
    let mut password = String::with_capacity(length);
    let mut last: Option<char> = None;

    for token in tokens {
        match token {
            PatternToken::Literal(c) => {
                password.push(c);
                last = Some(c);
            }
            PatternToken::Word => {
                let words = wordlist.unwrap();
                let word = words.choose(&mut rng).ok_or_else(|| {
                    PasswordGeneratorError::InvalidConfig(
                        "Cannot choose a word from an empty wordlist.".to_string(),
                    )
                })?;
                password.push_str(word);
                last = word.chars().last();
            }
            PatternToken::Class { symbol, count } => {
                let pool = pattern_pool(symbol, available_chars)?;
                for _ in 0..count {
                    if let Some(c) = choose_char(&pool, &mut rng, last, avoid_repetition) {
                        password.push(c);
                        last = Some(c);
                    }
                }
            }
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
    generate_passwords_with_wordlist(config, None).await
}

pub async fn generate_passwords_with_wordlist(
    config: &PasswordGeneratorConfig,
    wordlist_override: Option<&[String]>,
) -> Result<Vec<String>> {
    let mut passwords = Vec::with_capacity(config.num_passwords);
    for _ in 0..config.num_passwords {
        passwords.push(generate_password_with_wordlist(config, wordlist_override).await?);
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
    generate_password_with_min_entropy_and_wordlist(config, min_bits, None).await
}

pub async fn generate_password_with_min_entropy_and_wordlist(
    config: &PasswordGeneratorConfig,
    min_bits: f64,
    wordlist_override: Option<&[String]>,
) -> Result<String> {
    ensure_min_entropy_feasible(config, min_bits, None)?;
    for _ in 0..MIN_ENTROPY_MAX_ATTEMPTS {
        let mut password = if config.pronounceable {
            generate_pronounceable_password(config).await?
        } else {
            generate_password_with_wordlist(config, wordlist_override).await?
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
    generate_passwords_with_min_entropy_and_wordlist(config, min_bits, None).await
}

pub async fn generate_passwords_with_min_entropy_and_wordlist(
    config: &PasswordGeneratorConfig,
    min_bits: f64,
    wordlist_override: Option<&[String]>,
) -> Result<Vec<String>> {
    ensure_min_entropy_feasible(config, min_bits, None)?;
    let mut passwords = Vec::with_capacity(config.num_passwords);
    for _ in 0..config.num_passwords {
        passwords.push(
            generate_password_with_min_entropy_and_wordlist(config, min_bits, wordlist_override)
                .await?,
        );
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

fn build_salt_v2(service: &str, username: Option<&str>, counter: u32, block_index: u32) -> Vec<u8> {
    let mut salt = b"npwg:v2\0".to_vec();
    salt.extend_from_slice(&(service.len() as u64).to_be_bytes());
    salt.extend_from_slice(service.as_bytes());
    match username {
        None => salt.push(0),
        Some(username) => {
            salt.push(1);
            salt.extend_from_slice(&(username.len() as u64).to_be_bytes());
            salt.extend_from_slice(username.as_bytes());
        }
    }
    salt.extend_from_slice(&counter.to_be_bytes());
    salt.extend_from_slice(&block_index.to_be_bytes());
    salt
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

fn append_mapped_chars_v2(
    bytes: &[u8],
    alphabet: &[char],
    remaining: usize,
    output: &mut String,
) -> usize {
    let alphabet_len = alphabet.len() as u64;
    let value_range = u64::from(u32::MAX) + 1;
    let threshold = value_range / alphabet_len * alphabet_len;
    let mut appended = 0;
    for chunk in bytes.chunks_exact(4) {
        if appended == remaining {
            break;
        }
        let value = u64::from(u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
        if value < threshold {
            output.push(alphabet[(value % alphabet_len) as usize]);
            appended += 1;
        }
    }
    appended
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::strength::estimate_entropy_bits;

    #[test]
    fn deterministic_v2_salt_has_fixed_encoding() {
        let expected = b"npwg:v2\0\x00\x00\x00\x00\x00\x00\x00\x02\xc3\xa4\x01\x00\x00\x00\x00\x00\x00\x00\x03\xe2\x82\xac\x01\x02\x03\x04\x05\x06\x07\x08";
        assert_eq!(
            build_salt_v2("ä", Some("€"), 0x01020304, 0x05060708),
            expected
        );
    }

    #[test]
    fn deterministic_v2_salt_distinguishes_contexts() {
        assert_eq!(
            build_salt("a:b", Some("c"), 1, 0),
            build_salt("a", Some("b:c"), 1, 0)
        );
        assert_ne!(
            build_salt_v2("a:b", Some("c"), 1, 0),
            build_salt_v2("a", Some("b:c"), 1, 0)
        );
        assert_ne!(
            build_salt_v2("a:b", None, 1, 0),
            build_salt_v2("a", Some("b"), 1, 0)
        );
        assert_ne!(
            build_salt_v2("a", None, 1, 0),
            build_salt_v2("a", Some(""), 1, 0)
        );
        assert_ne!(
            build_salt_v2("a", Some("b"), 1, 0),
            build_salt_v2("a", Some("b"), 2, 0)
        );
        assert_ne!(
            build_salt_v2("a", Some("b"), 1, 0),
            build_salt_v2("a", Some("b"), 1, 1)
        );
    }

    #[test]
    fn deterministic_v2_mapping_handles_alphabet_boundaries() {
        for size in [1, 255, 256, 257] {
            let alphabet: Vec<_> = (0..size)
                .map(|i| char::from_u32(0x100 + i).unwrap())
                .collect();
            let mut output = String::new();
            let count = append_mapped_chars_v2(&[0, 0, 1, 0], &alphabet, 1, &mut output);
            assert_eq!(count, 1);
            assert_eq!(output, alphabet[256 % size as usize].to_string());
        }
    }

    #[test]
    fn deterministic_v2_mapping_rejects_outside_threshold() {
        for size in [255, 257] {
            let alphabet: Vec<_> = (0..size)
                .map(|i| char::from_u32(0x100 + i).unwrap())
                .collect();
            let mut output = String::new();
            let bytes = [u32::MAX.to_be_bytes(), (u32::MAX - 1).to_be_bytes()].concat();
            assert_eq!(append_mapped_chars_v2(&bytes, &alphabet, 2, &mut output), 1);
            assert_eq!(output, alphabet[(size - 1) as usize].to_string());
        }
    }

    #[test]
    fn deterministic_v2_mapping_accepts_full_range_for_divisors() {
        for size in [1, 256] {
            let alphabet: Vec<_> = (0..size)
                .map(|i| char::from_u32(0x100 + i).unwrap())
                .collect();
            let mut output = String::new();
            assert_eq!(
                append_mapped_chars_v2(&u32::MAX.to_be_bytes(), &alphabet, 1, &mut output),
                1
            );
            assert_eq!(output, alphabet[(size - 1) as usize].to_string());
        }
    }

    #[test]
    fn deterministic_v2_mapping_limits_characters_and_preserves_entries() {
        let mut output = "€".to_string();
        assert_eq!(
            append_mapped_chars_v2(&[0, 0, 0, 2, 0, 0, 0, 1], &['🔑', 'a', 'a'], 1, &mut output),
            1
        );
        assert_eq!(output, "€a");
        assert_eq!(append_mapped_chars_v2(&[0; 4], &['a'], 0, &mut output), 0);
        assert_eq!(output, "€a");
    }

    #[test]
    fn test_generate_with_pattern_rejects_pattern_longer_than_length() {
        let available_chars: Vec<char> = "abc123!".chars().collect();
        let result = generate_with_pattern("LLLLLLLLLL", &available_chars, 8, None, false, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_generate_with_pattern_rejects_unfulfillable_symbols() {
        let available_chars: Vec<char> = "abcdefg".chars().collect();
        let pattern = "LDLS";
        let length = 10;
        let seed = None;

        let result = generate_with_pattern(pattern, &available_chars, length, seed, false, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_generate_with_pattern_succeeds_when_satisfiable() {
        let available_chars: Vec<char> = "abc123!".chars().collect();
        let pattern = "LLDDS";
        let length = 8;
        let seed = Some(42);

        let password =
            generate_with_pattern(pattern, &available_chars, length, seed, false, None).unwrap();
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

    #[test]
    fn test_rich_pattern_literal_and_counts() {
        let available_chars: Vec<char> = "abc123!".chars().collect();
        let password =
            generate_with_pattern("{L:4}{D:2}-", &available_chars, 7, Some(1), false, None)
                .unwrap();
        assert_eq!(password.chars().count(), 7);
        assert_eq!(password.chars().nth(6), Some('-'));
        assert!(password.chars().take(4).all(|c| c.is_ascii_alphabetic()));
        assert!(password.chars().skip(4).take(2).all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn test_rich_pattern_word_token() {
        let available_chars: Vec<char> = "abc123!".chars().collect();
        let words = vec!["alpha".into(), "bravo".into()];
        let password = generate_with_pattern(
            "{word}-{D:2}",
            &available_chars,
            8,
            Some(2),
            false,
            Some(&words),
        )
        .unwrap();
        assert!(password.starts_with("alpha-") || password.starts_with("bravo-"));
        assert_eq!(password.chars().count(), 8);
    }

    #[test]
    fn test_pattern_needs_wordlist_detects_word_token() {
        assert!(pattern_needs_wordlist("{L:2}{word}"));
        assert!(!pattern_needs_wordlist("LLDDS"));
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
