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
pub mod stats;
pub mod strength;
#[cfg(test)]
pub mod tests;

pub use config::{PasswordGeneratorConfig, PasswordGeneratorMode};
pub use error::{PasswordGeneratorError, Result};
pub use generator::{
    generate_diceware_passphrase, generate_password, generate_passwords,
    generate_pronounceable_password, generate_pronounceable_passwords,
};
pub use stats::{show_stats, PasswordQuality};

pub async fn generate_password_with_config(config: &PasswordGeneratorConfig) -> Result<String> {
    if config.pronounceable {
        generate_pronounceable_password(config).await
    } else {
        generate_password(config).await
    }
}

pub async fn generate_passwords_with_config(
    config: &PasswordGeneratorConfig,
) -> Result<Vec<String>> {
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
