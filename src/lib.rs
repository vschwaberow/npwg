// SPDX-License-Identifier: MIT
// Project: npwg
// File: src/lib.rs
// Author: Volker Schwaberow <volker@schwaberow.de>
// Copyright (c) 2022 Volker Schwaberow

pub mod config;
pub mod diceware;
pub mod error;
pub mod generator;
pub mod interactive;
pub mod policy;
pub mod profile;
pub mod pwned;
pub mod stats;
pub mod strength;
#[cfg(test)]
pub mod tests;

pub use config::{PasswordGeneratorConfig, PasswordGeneratorMode};
pub use error::{PasswordGeneratorError, Result};
pub use generator::{
    effective_allowed_chars, generate_deterministic_password, generate_diceware_passphrase,
    generate_password, generate_passwords, generate_pronounceable_password,
    generate_pronounceable_passwords,
};
pub use stats::{show_stats, PasswordQuality};

pub async fn generate_password_with_config(config: &PasswordGeneratorConfig) -> Result<String> {
    if matches!(config.mode, PasswordGeneratorMode::Diceware) {
        return Err(PasswordGeneratorError::InvalidConfig(
            "Diceware mode requires generate_diceware_passphrase_with_config.".to_string(),
        ));
    }
    if config.pronounceable {
        generate_pronounceable_password(config).await
    } else {
        generate_password(config).await
    }
}

pub async fn generate_passwords_with_config(
    config: &PasswordGeneratorConfig,
) -> Result<Vec<String>> {
    if matches!(config.mode, PasswordGeneratorMode::Diceware) {
        return Err(PasswordGeneratorError::InvalidConfig(
            "Diceware mode requires generate_diceware_passphrase_with_config.".to_string(),
        ));
    }
    if config.pronounceable {
        generate_pronounceable_passwords(config).await
    } else {
        generate_passwords(config).await
    }
}

pub async fn generate_diceware_passphrase_with_config(
    wordlist: &[String],
    config: &PasswordGeneratorConfig,
) -> Result<Vec<String>> {
    generate_diceware_passphrase(wordlist, config).await
}

#[cfg(test)]
mod lib_api_tests {
    use super::*;

    #[tokio::test]
    async fn generate_password_with_config_rejects_diceware() {
        let mut config = PasswordGeneratorConfig::new();
        config.set_use_words(true);
        let err = generate_password_with_config(&config).await.unwrap_err();
        assert!(matches!(err, PasswordGeneratorError::InvalidConfig(_)));
    }

    #[tokio::test]
    async fn generate_passwords_with_config_rejects_diceware() {
        let mut config = PasswordGeneratorConfig::new();
        config.set_use_words(true);
        let err = generate_passwords_with_config(&config).await.unwrap_err();
        assert!(matches!(err, PasswordGeneratorError::InvalidConfig(_)));
    }
}
