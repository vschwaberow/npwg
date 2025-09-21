// SPDX-License-Identifier: MIT
// Project: npwg
// File: src/profile.rs
// Author: Volker Schwaberow <volker@schwaberow.de>

use crate::config::{PasswordGeneratorConfig, PasswordGeneratorMode, Separator, DEFINE};
use crate::error::{PasswordGeneratorError, Result};
use dirs::{config_dir, home_dir};
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

#[derive(Default, Deserialize)]
pub struct UserProfiles {
    #[serde(default)]
    defaults: Option<ProfileDefinition>,
    #[serde(default)]
    profiles: HashMap<String, ProfileDefinition>,
}

#[derive(Clone, Default, Deserialize)]
pub struct ProfileDefinition {
    length: Option<usize>,
    count: Option<usize>,
    allowed: Option<String>,
    avoid_repeating: Option<bool>,
    use_words: Option<bool>,
    separator: Option<String>,
    pronounceable: Option<bool>,
    pattern: Option<String>,
    seed: Option<u64>,
}

impl UserProfiles {
    pub fn defaults(&self) -> Option<&ProfileDefinition> {
        self.defaults.as_ref()
    }

    pub fn get(&self, name: &str) -> Option<&ProfileDefinition> {
        self.profiles.get(name)
    }
}

pub fn load_user_profiles(path_override: Option<&String>) -> Result<UserProfiles> {
    let path = determine_config_path(path_override);
    let Some(path) = path else {
        return Ok(UserProfiles::default());
    };
    if !path.exists() {
        return Ok(UserProfiles::default());
    }
    let contents = fs::read_to_string(&path).map_err(|error| {
        PasswordGeneratorError::ConfigFile(format!("Failed to read {}: {}", path.display(), error))
    })?;
    let profiles: UserProfiles = toml::from_str(&contents).map_err(|error| {
        PasswordGeneratorError::ConfigFile(format!(
            "Invalid config in {}: {}",
            path.display(),
            error
        ))
    })?;
    Ok(profiles)
}

pub fn apply_profile(
    profile: &ProfileDefinition,
    config: &mut PasswordGeneratorConfig,
) -> Result<()> {
    if let Some(length) = profile.length {
        config.length = length;
    }
    if let Some(count) = profile.count {
        config.num_passwords = count;
    }
    if let Some(avoid) = profile.avoid_repeating {
        config.set_avoid_repeating(avoid);
    }
    if let Some(seed) = profile.seed {
        config.seed = Some(seed);
    }
    if let Some(pronounceable) = profile.pronounceable {
        config.pronounceable = pronounceable;
    }
    if let Some(pattern) = profile.pattern.as_ref() {
        config.pattern = Some(pattern.clone());
    }
    if let Some(allowed) = profile.allowed.as_ref() {
        apply_allowed_sets(config, allowed)?;
    }
    if let Some(use_words) = profile.use_words {
        config.set_use_words(use_words);
        if use_words {
            if config.separator.is_none() {
                config.separator = Some(Separator::Fixed(' '));
            }
        } else {
            config.separator = None;
        }
    }
    if let Some(value) = profile.separator.as_ref() {
        config.separator = Some(parse_separator(value)?);
    }
    Ok(())
}

fn determine_config_path(path_override: Option<&String>) -> Option<PathBuf> {
    if let Some(path) = path_override {
        return Some(PathBuf::from(path));
    }
    if let Some(dir) = config_dir() {
        return Some(dir.join("npwg").join("config.toml"));
    }
    home_dir().map(|home| home.join(".npwg").join("config.toml"))
}

pub fn apply_allowed_sets(config: &mut PasswordGeneratorConfig, allowed: &str) -> Result<()> {
    config.clear_allowed_chars();
    for charset in allowed
        .split(',')
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
    {
        if !DEFINE.iter().any(|&(name, _)| name == charset) {
            return Err(PasswordGeneratorError::ConfigFile(format!(
                "Unknown characterset '{}' in config",
                charset
            )));
        }
        config.add_allowed_chars(charset);
    }
    if config.allowed_chars.is_empty() {
        return Err(PasswordGeneratorError::ConfigFile(
            "Allowed character set resolved to empty".to_string(),
        ));
    }
    Ok(())
}

pub fn parse_separator(value: &str) -> Result<Separator> {
    if value == "random" {
        let chars: Vec<char> = ('a'..='z').chain('0'..='9').collect();
        return Ok(Separator::Random(chars));
    }
    if value.chars().count() == 1 {
        let separator = value.chars().next().unwrap();
        return Ok(Separator::Fixed(separator));
    }
    Err(PasswordGeneratorError::ConfigFile(
        "Separator must be a single character or 'random'".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_profile_overrides_defaults() {
        let mut config = PasswordGeneratorConfig::new();
        let profile = ProfileDefinition {
            length: Some(24),
            count: Some(3),
            allowed: Some("upperletter,lowerletter".to_string()),
            avoid_repeating: Some(true),
            use_words: Some(true),
            separator: Some("-".to_string()),
            pronounceable: Some(false),
            pattern: Some("LLDDS".to_string()),
            seed: Some(99),
        };
        apply_profile(&profile, &mut config).unwrap();
        assert_eq!(config.length, 24);
        assert_eq!(config.num_passwords, 3);
        assert!(config.avoid_repetition);
        assert_eq!(config.seed, Some(99));
        assert_eq!(config.pattern.as_deref(), Some("LLDDS"));
        assert!(matches!(config.mode, PasswordGeneratorMode::Diceware));
        match config.separator.as_ref().unwrap() {
            Separator::Fixed(value) => assert_eq!(*value, '-'),
            _ => panic!(),
        }
        assert_eq!(config.allowed_chars.len(), 52);
    }

    #[test]
    fn parse_separator_errors_for_invalid_values() {
        let error = parse_separator("too-long").err().unwrap();
        match error {
            PasswordGeneratorError::ConfigFile(message) => assert!(message.contains("Separator")),
            _ => panic!(),
        }
    }
}
