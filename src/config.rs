// SPDX-License-Identifier: MIT
// Project: npwg
// File: src/config.rs
// Author: Volker Schwaberow <volker@schwaberow.de>
// Copyright (c) 2022 Volker Schwaberow

use crate::error::{PasswordGeneratorError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

pub const DEFINE: &[(&str, &str)] = &[
    ("symbol1", "#%&?@"),
    ("symbol2", "!#$%&*+-./:=?@~"),
    ("symbol3", "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"),
    ("digit", "0123456789"),
    ("lowerletter", "abcdefghijklmnopqrstuvwxyz"),
    ("upperletter", "ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
    ("shell", "!\"$&`'"),
    ("homoglyph1", "71lI|"),
    ("homoglyph2", "2Z"),
    ("homoglyph3", "6G"),
    ("homoglyph4", ":;"),
    ("homoglyph5", "^`'"),
    ("homoglyph6", "!|"),
    ("homoglyph7", "<({[]})>"),
    ("homoglyph8", "~-"),
    ("slashes", "/\\"),
    ("brackets", "[]{}()"),
    ("punctuation", "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"),
    ("all", "#%&?@!#$%&*+-./:=?@~0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~!\"$&`'71lI|2Z6G:;^`'!|<({[]})>~-/\\[]{}()!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"),
    ("allprint", "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"),
    ("allprintnoquote", "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!#$%&()*+,-./:;<=>?@[\\]^_`{|}~"),
    ("allprintnospace", "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"),
    ("allprintnospacequote", "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!#$%&()*+,-./:;<=>?@[\\]^_`{|}~"),
    ("allprintnospacequotebracket", "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!#$%&()*+,-./:;<=>?@[\\]^_`{|}~[]{}()"),
    ("allprintnospacequotebracketpunctuation", "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!#$%&()*+,-./:;<=>?@[\\]^_`{|}~[]{}()!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"),
    ("allprintnospacequotebracketpunctuationslashes", "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!#$%&()*+,-.:;<=>?@[\\]^_`{|}~[]{}()!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"),
    ("allprintnospacequotebracketpunctuationslashesshell", "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ#$%&()*+,-.:;<=>?@[\\]^_`{|}~[]"),
];

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PasswordGeneratorMode {
    Password,
    Diceware,
}

pub enum Separator {
    Fixed(char),
    Random(Vec<char>),
}

pub struct PasswordGeneratorConfig {
    pub length: usize,
    pub allowed_chars: Vec<char>,
    pub excluded_chars: HashSet<char>,
    pub included_chars: HashSet<char>,
    pub avoid_repetition: bool,
    pub mode: PasswordGeneratorMode,
    pub diceware_words: usize,
    pub num_passwords: usize,
    pub separator: Option<Separator>,
}

impl Default for PasswordGeneratorConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl PasswordGeneratorConfig {
    pub fn new() -> Self {
        let mut config = Self {
            length: 8,
            allowed_chars: Vec::new(),
            excluded_chars: HashSet::new(),
            included_chars: HashSet::new(),
            num_passwords: 1,
            avoid_repetition: false,
            mode: PasswordGeneratorMode::Password,
            diceware_words: 6,
            separator: None,
        };
        config.set_allowed_chars("allprint");
        config
    }

    pub fn set_allowed_chars(&mut self, charset_name: &str) {
        if let Some((_, chars)) = DEFINE.iter().find(|(name, _)| *name == charset_name) {
            self.allowed_chars = chars.chars().collect();
        } else {
            if let Some((_, chars)) = DEFINE.iter().find(|(name, _)| *name == "allprint") {
                self.allowed_chars = chars.chars().collect();
            }
        }
    }

    pub fn add_allowed_chars(&mut self, charset_name: &str) {
        if let Some((_, chars)) = DEFINE.iter().find(|(name, _)| *name == charset_name) {
            self.allowed_chars.extend(chars.chars());
        }
    }

    pub fn clear_allowed_chars(&mut self) {
        self.allowed_chars.clear();
    }

    pub fn set_avoid_repeating(&mut self, avoid: bool) {
        self.avoid_repetition = avoid;
    }

    pub fn validate(&self) -> Result<()> {
        if self.allowed_chars.is_empty() {
            return Err(PasswordGeneratorError::InvalidConfig(
                "No allowed characters specified".to_string(),
            ));
        }
        if self.length == 0 {
            return Err(PasswordGeneratorError::InvalidConfig(
                "Password length must be greater than 0".to_string(),
            ));
        }
        if self.num_passwords == 0 {
            return Err(PasswordGeneratorError::InvalidConfig(
                "Number of passwords must be greater than 0".to_string(),
            ));
        }
        Ok(())
    }
    pub fn set_use_words(&mut self, use_words: bool) {
        self.mode = if use_words {
            PasswordGeneratorMode::Diceware
        } else {
            PasswordGeneratorMode::Password
        };
    }
}
