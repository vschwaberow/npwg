// SPDX-License-Identifier: MIT
// Project: npwg
// File: src/strength.rs
// Author: Volker Schwaberow <volker@schwaberow.de>
// Copyright (c) 2022 Volker Schwaberow

use std::collections::HashSet;

pub fn evaluate_password_strength(password: &str) -> f64 {
    let length = password.len() as f64;
    let char_set_size = get_char_set_size(password) as f64;
    let entropy = length * char_set_size.log2();

    let normalized_score = (entropy / 128.0).min(1.0);

    let penalized_score = apply_penalties(password, normalized_score);

    penalized_score
}

fn get_char_set_size(password: &str) -> usize {
    let mut char_set = HashSet::new();
    for c in password.chars() {
        if c.is_ascii_lowercase() {
            char_set.insert('a');
        } else if c.is_ascii_uppercase() {
            char_set.insert('A');
        } else if c.is_ascii_digit() {
            char_set.insert('0');
        } else {
            char_set.insert('!');
        }
    }
    char_set.len()
}

fn apply_penalties(password: &str, score: f64) -> f64 {
    let mut penalized_score = score;

    if has_sequential_chars(password) {
        penalized_score *= 0.8;
    }

    if has_repeated_chars(password) {
        penalized_score *= 0.9;
    }

    if contains_common_word(password) {
        penalized_score *= 0.7;
    }

    penalized_score
}

fn has_sequential_chars(password: &str) -> bool {
    let chars: Vec<char> = password.chars().collect();
    for window in chars.windows(3) {
        if window[0] as u32 + 1 == window[1] as u32 && window[1] as u32 + 1 == window[2] as u32 {
            return true;
        }
    }
    false
}

fn has_repeated_chars(password: &str) -> bool {
    let chars: Vec<char> = password.chars().collect();
    for window in chars.windows(3) {
        if window[0] == window[1] && window[1] == window[2] {
            return true;
        }
    }
    false
}

fn contains_common_word(password: &str) -> bool {
    let common_words = ["password", "123456", "qwerty", "admin", "letmein"];
    for word in common_words.iter() {
        if password.to_lowercase().contains(word) {
            return true;
        }
    }
    false
}

pub fn get_strength_feedback(score: f64) -> String {
    match score {
        s if s < 0.2 => "Very Weak".to_string(),
        s if s < 0.4 => "Weak".to_string(),
        s if s < 0.6 => "Moderate".to_string(),
        s if s < 0.8 => "Strong".to_string(),
        _ => "Very Strong".to_string(),
    }
}

pub fn get_strength_bar(score: f64) -> String {
    let bar_length = 20;
    let filled_length = (score * bar_length as f64).round() as usize;
    let empty_length = bar_length - filled_length;

    let filled = "█".repeat(filled_length);
    let empty = "░".repeat(empty_length);

    format!("[{}{}]", filled, empty)
}
