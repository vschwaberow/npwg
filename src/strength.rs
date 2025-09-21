// SPDX-License-Identifier: MIT
// Project: npwg
// File: src/strength.rs
// Author: Volker Schwaberow <volker@schwaberow.de>
// Copyright (c) 2022 Volker Schwaberow

use std::collections::{HashMap, HashSet};
use std::f64;

/// Evaluates password strength using a comprehensive multi-factor analysis approach.
///
/// This implementation is based on multiple academic research papers on password security:
/// - Shannon entropy calculation for character-set complexity
/// - NIST SP 800-63B guideline compliance
/// - Pattern-based vulnerability detection (similar to zxcvbn)
/// - Markov model principles for sequential probability
///
/// Returns a normalized score between 0.0 and 1.0 where:
/// - 0.0-0.3: Very weak to weak
/// - 0.3-0.6: Moderate
/// - 0.6-0.8: Strong
/// - 0.8-1.0: Very strong
pub fn evaluate_password_strength(password: &str) -> f64 {
    // Calculate multiple metrics
    let _length = password.len() as f64;
    let entropy_score = calculate_entropy(password);
    let pattern_penalty = detect_patterns(password);
    let diversity_score = calculate_diversity(password);
    let nist_compliance_score = check_nist_compliance(password);

    // Weighted combination of metrics (weights determined by empirical testing)
    let weighted_score = ((entropy_score * 0.45)
        + (diversity_score * 0.25)
        + (nist_compliance_score * 0.15)
        + (pattern_penalty * 0.15))
        .min(1.0);

    weighted_score
}

/// Calculates Shannon entropy with adjustments for actual character distribution
pub fn calculate_entropy(password: &str) -> f64 {
    if password.is_empty() {
        return 0.0;
    }

    let mut char_counts = HashMap::new();
    for c in password.chars() {
        *char_counts.entry(c).or_insert(0) += 1;
    }

    let len = password.len() as f64;
    let mut entropy = 0.0;
    for count in char_counts.values() {
        let probability = (*count as f64) / len;
        entropy -= probability * probability.log2();
    }

    let char_set_size = get_theoretical_char_set_size(password) as f64;

    if char_set_size == 0.0 {
        return 0.0;
    }

    let log2_char_set_size = char_set_size.log2();

    let normalized_entropy = if log2_char_set_size > 0.0 {
        (entropy / log2_char_set_size).min(1.0)
    } else {
        0.0
    };

    let length_factor = 1.0 - (1.0 / (0.3 * len + 1.0));
    let weighted_score = normalized_entropy * 0.7 + length_factor * 0.3;
    weighted_score.max(0.0).min(1.0)
}

/// Detects common patterns in passwords and returns a penalty score
/// Lower score means more patterns detected (worse password)
fn detect_patterns(password: &str) -> f64 {
    let mut score = 1.0;
    let lowercase = password.to_lowercase();

    // Detect sequential characters (abc, 123, etc.)
    if has_sequential_chars(password) {
        score *= 0.9;
    }

    // Detect repeated characters (aaa, 111, etc.)
    if has_repeated_chars(password) {
        score *= 0.85;
    }

    // Check for keyboard patterns (qwerty, asdfgh, etc.)
    if has_keyboard_pattern(password) {
        score *= 0.8;
    }

    // Check for common words, names, or dates
    if contains_common_word(&lowercase) {
        score *= 0.7;
    }

    // Check for leetspeak substitutions (p@ssw0rd)
    if contains_leetspeak(&lowercase) {
        score *= 0.9;
    }

    // Check for date patterns (MMDDYYYY, DDMMYYYY, etc.)
    if contains_date_pattern(password) {
        score *= 0.85;
    }

    score
}

/// Calculates character diversity score based on unique character types and distribution
fn calculate_diversity(password: &str) -> f64 {
    let mut char_types = HashSet::new();
    let total_chars = password.len() as f64;

    // Count frequencies of different character types
    let mut lowercase_count = 0;
    let mut uppercase_count = 0;
    let mut digit_count = 0;
    let mut symbol_count = 0;
    let mut other_count = 0;

    for c in password.chars() {
        if c.is_ascii_lowercase() {
            char_types.insert("lowercase");
            lowercase_count += 1;
        } else if c.is_ascii_uppercase() {
            char_types.insert("uppercase");
            uppercase_count += 1;
        } else if c.is_ascii_digit() {
            char_types.insert("digit");
            digit_count += 1;
        } else if c.is_ascii_punctuation() {
            char_types.insert("punctuation");
            symbol_count += 1;
        } else {
            char_types.insert("other");
            other_count += 1;
        }
    }

    // Calculate character type diversity (0.0 to 1.0)
    let type_diversity = (char_types.len() as f64 / 5.0).min(1.0);

    // Calculate distribution uniformity (higher is better)
    let mut distribution_score = 1.0;
    if total_chars > 0.0 {
        let type_counts = [
            lowercase_count as f64 / total_chars,
            uppercase_count as f64 / total_chars,
            digit_count as f64 / total_chars,
            symbol_count as f64 / total_chars,
            other_count as f64 / total_chars,
        ];

        for count in type_counts.iter() {
            if *count > 0.8 {
                // Penalize if one type dominates (>80%)
                distribution_score *= 0.85;
                break;
            }
        }
    }

    // Weight type diversity more than distribution
    (type_diversity * 0.8 + distribution_score * 0.2).min(1.0)
}

/// Checks password against NIST SP 800-63B guidelines
fn check_nist_compliance(password: &str) -> f64 {
    let mut score = 1.0;

    // NIST guideline: Minimum 8 characters
    if password.len() < 8 {
        score *= 0.5;
    }

    // Check for repetition of the same character
    if password.len() > 1 {
        let chars: Vec<char> = password.chars().collect();
        for i in 1..chars.len() {
            if chars[i] == chars[i - 1] {
                let repetition_penalty = 0.98;
                score *= repetition_penalty; // Small penalty for each repetition
            }
        }
    }

    // Check if password appears in common password lists (simplified check)
    if contains_common_password(password) {
        score *= 0.3; // Significant penalty for common passwords
    }

    score
}

/// Determines the theoretical character set size based on character types present
pub fn get_theoretical_char_set_size(password: &str) -> usize {
    if password.is_empty() {
        return 0;
    }

    let mut char_sets = HashSet::new();
    for c in password.chars() {
        if c.is_ascii_lowercase() {
            char_sets.insert("lowercase");
        } else if c.is_ascii_uppercase() {
            char_sets.insert("uppercase");
        } else if c.is_ascii_digit() {
            char_sets.insert("digit");
        } else if c.is_ascii_punctuation() {
            char_sets.insert("punctuation");
        } else {
            char_sets.insert("other");
        }
    }

    const LOWERCASE_SIZE: usize = 26;
    const UPPERCASE_SIZE: usize = 26;
    const DIGIT_SIZE: usize = 10;
    const PUNCTUATION_CHAR_SET: &str = "!\"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~";
    const PUNCTUATION_SIZE: usize = 32; //PUNCTUATION_CHAR_SET.chars().count();

    let mut total_size = 0;
    let mut has_known_ascii_type = false;

    if char_sets.contains("lowercase") {
        total_size += LOWERCASE_SIZE;
        has_known_ascii_type = true;
    }
    if char_sets.contains("uppercase") {
        total_size += UPPERCASE_SIZE;
        has_known_ascii_type = true;
    }
    if char_sets.contains("digit") {
        total_size += DIGIT_SIZE;
        has_known_ascii_type = true;
    }
    if char_sets.contains("punctuation") {
        total_size += PUNCTUATION_SIZE;
        has_known_ascii_type = true;
    }

    if char_sets.contains("other") {
        let unique_other_chars_count = password
            .chars()
            .filter(|c| {
                !c.is_ascii_lowercase()
                    && !c.is_ascii_uppercase()
                    && !c.is_ascii_digit()
                    && !PUNCTUATION_CHAR_SET.contains(*c)
            })
            .collect::<HashSet<char>>()
            .len();

        if !has_known_ascii_type {
            total_size = unique_other_chars_count;
        } else {
            total_size += unique_other_chars_count;
        }
    }

    if total_size == 0 && !password.is_empty() {
        return password.chars().collect::<HashSet<char>>().len().max(1);
    }

    total_size.max(1)
}

/// Detects sequential characters in the password
fn has_sequential_chars(password: &str) -> bool {
    // ASCII sequences
    let chars: Vec<char> = password.chars().collect();
    for window in chars.windows(3) {
        if (window[0] as u32 + 1 == window[1] as u32 && window[1] as u32 + 1 == window[2] as u32)
            || (window[0] as u32 - 1 == window[1] as u32
                && window[1] as u32 - 1 == window[2] as u32)
        {
            return true;
        }
    }

    // Alphabetical sequences like "abc", "xyz"
    let alphabet = "abcdefghijklmnopqrstuvwxyz";
    for i in 0..alphabet.len() - 2 {
        if password.to_lowercase().contains(&alphabet[i..i + 3]) {
            return true;
        }
    }

    // Number sequences
    let numbers = "0123456789";
    for i in 0..numbers.len() - 2 {
        if password.contains(&numbers[i..i + 3]) {
            return true;
        }
    }

    false
}

/// Detects repeated characters in the password
fn has_repeated_chars(password: &str) -> bool {
    let chars: Vec<char> = password.chars().collect();
    for window in chars.windows(3) {
        if window[0] == window[1] && window[1] == window[2] {
            return true;
        }
    }
    false
}

/// Detects keyboard patterns in the password
fn has_keyboard_pattern(password: &str) -> bool {
    let keyboard_patterns = [
        "qwerty", "asdfgh", "zxcvbn", "qwertz", "azerty", "1qaz", "2wsx", "3edc", "4rfv", "5tgb",
        "6yhn", "7ujm", "8ik,", "9ol.", "0p;/", "-['", "=]\\",
    ];

    let lowercase = password.to_lowercase();
    for pattern in keyboard_patterns.iter() {
        if lowercase.contains(pattern) {
            return true;
        }
    }
    false
}

/// Checks if the password contains common words or names
fn contains_common_word(password: &str) -> bool {
    let common_words = [
        "password", "123456", "qwerty", "admin", "welcome", "letmein", "monkey", "dragon",
        "baseball", "football", "master", "hello", "login", "abc123", "sunshine", "princess",
        "starwars", "access", "shadow", "michael", "batman", "superman", "love", "summer",
        "winter", "spring", "autumn", "secret",
    ];

    for word in common_words.iter() {
        if password.contains(word) {
            return true;
        }
    }
    false
}

/// Detects leetspeak substitutions in the password
fn contains_leetspeak(password: &str) -> bool {
    let leetspeak_words = [
        "p@ssw0rd", "p455w0rd", "passw0rd", "pa55word", "l3tm31n", "adm1n",
    ];

    for word in leetspeak_words.iter() {
        if password.contains(word) {
            return true;
        }
    }

    // Check for patterns of leetspeak substitutions
    let mut contains_substitution = false;
    if password.contains('0') && password.contains('o') {
        contains_substitution = true;
    } else if password.contains('1') && password.contains('i') {
        contains_substitution = true;
    } else if password.contains('@') && password.contains('a') {
        contains_substitution = true;
    } else if password.contains('3') && password.contains('e') {
        contains_substitution = true;
    } else if password.contains('5') && password.contains('s') {
        contains_substitution = true;
    }

    contains_substitution
}

/// Detects date patterns in the password
fn contains_date_pattern(password: &str) -> bool {
    // Check for common date formats: MMDDYYYY, DDMMYYYY, MMDDYY, DDMMYY, etc.
    let digits: String = password.chars().filter(|c| c.is_ascii_digit()).collect();

    if digits.len() >= 6 {
        if digits.len() == 6 || digits.len() == 8 {
            // Simple validation for plausible date components
            let possible_month = &digits[0..2];
            let possible_day = &digits[2..4];

            let month = possible_month.parse::<u32>().unwrap_or(0);
            let day = possible_day.parse::<u32>().unwrap_or(0);

            if (month >= 1 && month <= 12) && (day >= 1 && day <= 31) {
                return true;
            }

            // Check alternate format (day/month instead of month/day)
            let alt_month = possible_day;
            let alt_day = possible_month;

            let alt_month_val = alt_month.parse::<u32>().unwrap_or(0);
            let alt_day_val = alt_day.parse::<u32>().unwrap_or(0);

            if (alt_month_val >= 1 && alt_month_val <= 12)
                && (alt_day_val >= 1 && alt_day_val <= 31)
            {
                return true;
            }
        }
    }

    false
}

/// Checks if the password appears in the list of commonly used passwords
fn contains_common_password(password: &str) -> bool {
    let common_passwords = [
        "123456",
        "password",
        "12345678",
        "qwerty",
        "123456789",
        "12345",
        "1234",
        "111111",
        "1234567",
        "dragon",
        "123123",
        "baseball",
        "abc123",
        "football",
        "monkey",
        "letmein",
        "shadow",
        "master",
        "666666",
        "qwertyuiop",
        "123321",
        "mustang",
        "1234567890",
        "michael",
        "654321",
        "superman",
        "1qaz2wsx",
        "7777777",
        "121212",
        "000000",
        "qazwsx",
        "123qwe",
        "killer",
        "trustno1",
        "jordan",
        "jennifer",
        "hunter",
        "buster",
        "soccer",
        "harley",
        "batman",
        "andrew",
        "tigger",
        "sunshine",
        "iloveyou",
        "2000",
        "charlie",
        "robert",
        "thomas",
        "hockey",
        "ranger",
        "daniel",
        "starwars",
        "klaster",
        "112233",
        "george",
        "computer",
        "michelle",
        "jessica",
        "pepper",
        "1111",
        "zxcvbn",
        "555555",
        "11111111",
        "131313",
        "freedom",
        "777777",
        "pass",
        "maggie",
        "159753",
        "aaaaaa",
        "ginger",
        "princess",
        "joshua",
        "cheese",
        "amanda",
        "summer",
        "love",
        "ashley",
        "nicole",
        "chelsea",
        "biteme",
        "matthew",
        "access",
        "yankees",
        "987654321",
        "dallas",
        "austin",
        "thunder",
        "taylor",
    ];

    common_passwords.contains(&password.to_lowercase().as_str())
}

/// Returns verbal feedback on password strength
pub fn get_strength_feedback(score: f64) -> String {
    match score {
        s if s < 0.2 => "Very Weak".to_string(),
        s if s < 0.4 => "Weak".to_string(),
        s if s < 0.6 => "Moderate".to_string(),
        s if s < 0.8 => "Strong".to_string(),
        _ => "Very Strong".to_string(),
    }
}

/// Gets specific improvement suggestions based on password analysis
pub fn get_improvement_suggestions(password: &str) -> Vec<String> {
    let mut suggestions = Vec::new();

    if password.len() < 12 {
        suggestions.push("Increase password length to at least 12 characters".to_string());
    }

    let mut has_lowercase = false;
    let mut has_uppercase = false;
    let mut has_digit = false;
    let mut has_symbol = false;

    for c in password.chars() {
        if c.is_ascii_lowercase() {
            has_lowercase = true;
        } else if c.is_ascii_uppercase() {
            has_uppercase = true;
        } else if c.is_ascii_digit() {
            has_digit = true;
        } else if c.is_ascii_punctuation() {
            has_symbol = true;
        }
    }

    if !has_lowercase {
        suggestions.push("Add lowercase letters".to_string());
    }
    if !has_uppercase {
        suggestions.push("Add uppercase letters".to_string());
    }
    if !has_digit {
        suggestions.push("Add digits".to_string());
    }
    if !has_symbol {
        suggestions.push("Add special characters".to_string());
    }

    if has_sequential_chars(password) {
        suggestions.push("Avoid sequential characters (abc, 123)".to_string());
    }

    if has_repeated_chars(password) {
        suggestions.push("Avoid repeated characters (aaa, 111)".to_string());
    }

    if has_keyboard_pattern(password) {
        suggestions.push("Avoid keyboard patterns (qwerty, asdfgh)".to_string());
    }

    if contains_common_word(&password.to_lowercase()) {
        suggestions.push("Avoid common words or phrases".to_string());
    }

    if contains_date_pattern(password) {
        suggestions.push("Avoid using dates in your password".to_string());
    }

    suggestions
}

/// Creates a visual strength bar representation
pub fn get_strength_bar(score: f64) -> String {
    let bar_length = 20;
    let filled_length = (score * bar_length as f64).round() as usize;
    let empty_length = bar_length - filled_length;

    let filled = "█".repeat(filled_length);
    let empty = "░".repeat(empty_length);

    format!("[{}{}]", filled, empty)
}
