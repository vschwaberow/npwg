// SPDX-License-Identifier: MIT
// Project: npwg
// File: src/diceware.rs
// Author: Volker Schwaberow <volker@schwaberow.de>
// Copyright (c) 2022 Volker Schwaberow

use crate::error::PasswordGeneratorError;
use crate::error::Result;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

const MIN_CUSTOM_WORDS: usize = 2;
const EFF_LARGE_EMBEDDED: &str = include_str!("../assets/eff_large_wordlist.txt");
const EFF_SHORT_EMBEDDED: &str = include_str!("../assets/eff_short_wordlist_1.txt");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WordlistPreset {
    EffLarge,
    EffShort,
}

impl WordlistPreset {
    pub fn parse(raw: &str) -> Result<Self> {
        match raw {
            "eff-large" | "large" => Ok(Self::EffLarge),
            "eff-short" | "short" => Ok(Self::EffShort),
            other => Err(PasswordGeneratorError::InvalidConfig(format!(
                "Unknown wordlist preset '{}'. Use eff-large or eff-short.",
                other
            ))),
        }
    }

    fn expected_lines(self) -> usize {
        match self {
            Self::EffLarge => 7776,
            Self::EffShort => 1296,
        }
    }

    fn expected_sha256(self) -> &'static str {
        match self {
            Self::EffLarge => "addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e",
            Self::EffShort => "8f5ca830b8bffb6fe39c9736c024a00a6a6411adb3f83a9be8bfeeb6e067ae69",
        }
    }

    fn embedded(self) -> &'static str {
        match self {
            Self::EffLarge => EFF_LARGE_EMBEDDED,
            Self::EffShort => EFF_SHORT_EMBEDDED,
        }
    }
}

#[derive(Debug, Clone)]
pub enum WordlistSource {
    Preset(WordlistPreset),
    Path(PathBuf),
}

impl Default for WordlistSource {
    fn default() -> Self {
        Self::Preset(WordlistPreset::EffLarge)
    }
}

pub async fn get_wordlist(source: &WordlistSource) -> Result<Vec<String>> {
    match source {
        WordlistSource::Preset(preset) => load_embedded_preset(*preset),
        WordlistSource::Path(path) => load_custom_wordlist(path),
    }
}

fn load_embedded_preset(preset: WordlistPreset) -> Result<Vec<String>> {
    let contents = preset.embedded();
    validate_embedded_wordlist(contents, preset)?;
    let words = parse_wordlist(contents);
    if words.len() != preset.expected_lines() {
        return Err(PasswordGeneratorError::WordlistValidation(format!(
            "Expected {} words in embedded {}, parsed {}",
            preset.expected_lines(),
            preset_label(preset),
            words.len()
        )));
    }
    Ok(words)
}

fn preset_label(preset: WordlistPreset) -> &'static str {
    match preset {
        WordlistPreset::EffLarge => "eff-large",
        WordlistPreset::EffShort => "eff-short",
    }
}

fn load_custom_wordlist(wordlist_path: &Path) -> Result<Vec<String>> {
    let contents = fs::read_to_string(wordlist_path).map_err(|e| {
        PasswordGeneratorError::WordlistValidation(format!(
            "Failed to read wordlist {}: {}",
            wordlist_path.display(),
            e
        ))
    })?;
    let words = parse_wordlist(&contents);
    if words.len() < MIN_CUSTOM_WORDS {
        return Err(PasswordGeneratorError::WordlistValidation(format!(
            "Custom wordlist {} must contain at least {} words (found {}).",
            wordlist_path.display(),
            MIN_CUSTOM_WORDS,
            words.len()
        )));
    }
    Ok(words)
}

fn parse_wordlist(contents: &str) -> Vec<String> {
    contents
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() {
                return None;
            }
            if let Some((_, word)) = line.split_once('\t') {
                let word = word.trim();
                if word.is_empty() {
                    None
                } else {
                    Some(word.to_string())
                }
            } else {
                Some(line.to_string())
            }
        })
        .collect()
}

fn hex_sha256(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .map(|byte| format!("{:02x}", byte))
        .collect()
}

fn validate_embedded_wordlist(contents: &str, preset: WordlistPreset) -> Result<()> {
    let line_count = contents.lines().count();
    if line_count != preset.expected_lines() {
        return Err(PasswordGeneratorError::WordlistValidation(format!(
            "Expected {} entries in embedded {}, found {}",
            preset.expected_lines(),
            preset_label(preset),
            line_count
        )));
    }

    let checksum = hex_sha256(contents.as_bytes());
    if checksum != preset.expected_sha256() {
        return Err(PasswordGeneratorError::WordlistValidation(format!(
            "Checksum mismatch for embedded {}.",
            preset_label(preset)
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn preset_metadata_matches_known_sizes() {
        assert_eq!(WordlistPreset::EffLarge.expected_lines(), 7776);
        assert_eq!(WordlistPreset::EffShort.expected_lines(), 1296);
    }

    #[test]
    fn embedded_presets_parse_expected_word_counts() {
        let large = load_embedded_preset(WordlistPreset::EffLarge).unwrap();
        let short = load_embedded_preset(WordlistPreset::EffShort).unwrap();
        assert_eq!(large.len(), 7776);
        assert_eq!(short.len(), 1296);
    }

    #[test]
    fn parse_wordlist_accepts_tab_and_plain_lines() {
        let words = parse_wordlist("1111\tacid\nplain\n\n2222\tacorn\n");
        assert_eq!(words, vec!["acid", "plain", "acorn"]);
    }

    #[test]
    fn load_custom_wordlist_rejects_too_few_words() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "only-one").unwrap();
        let err = load_custom_wordlist(file.path()).unwrap_err();
        assert!(matches!(err, PasswordGeneratorError::WordlistValidation(_)));
    }

    #[test]
    fn load_custom_wordlist_accepts_minimal_list() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "alpha\nbravo").unwrap();
        let words = load_custom_wordlist(file.path()).unwrap();
        assert_eq!(words, vec!["alpha", "bravo"]);
    }

    #[test]
    fn wordlist_preset_parse() {
        assert_eq!(
            WordlistPreset::parse("eff-short").unwrap(),
            WordlistPreset::EffShort
        );
        assert!(WordlistPreset::parse("nope").is_err());
    }
}
