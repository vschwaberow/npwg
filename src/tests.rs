// SPDX-License-Identifier: MIT
// Project: npwg
// File: src/tests.rs
// Author: Volker Schwaberow <volker@schwaberow.de>
// Copyright (c) 2022 Volker Schwaberow

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PasswordGeneratorConfig;
    use crate::generator::{generate_diceware_passphrase, generate_password, generate_passwords};
    use crate::stats::show_stats;

    #[tokio::test]
    async fn test_password_generator_config_new() {
        let mut config = PasswordGeneratorConfig::new();
        config.set_allowed_chars_default();
        assert_eq!(config.length, 8);
        assert_eq!(config.allowed_chars.len(), 45);
        assert!(config.excluded_chars.is_empty());
        assert!(config.included_chars.is_empty());
        assert_eq!(config.num_passwords, 1);
    }

    #[test]
    fn test_password_generator_config_validate() {
        let mut config = PasswordGeneratorConfig::new();
        config.set_allowed_chars_default();
        assert!(config.validate().is_ok());

        config.allowed_chars.clear();
        assert!(config.validate().is_err());
    }

    #[tokio::test]
    async fn test_generate_password() {
        let mut config = PasswordGeneratorConfig::new();
        config.set_allowed_chars_default();
        let password = generate_password(&config).await;
        assert_eq!(password.len(), 8);
    }

    #[tokio::test]
    async fn test_generate_diceware_passphrase() {
        let wordlist = vec![
            "apple".to_string(),
            "banana".to_string(),
            "cherry".to_string(),
            "date".to_string(),
            "elderberry".to_string(),
        ];

        let passphrase = generate_diceware_passphrase(&wordlist, 4).await;

        let words: Vec<&str> = passphrase.split_whitespace().collect();
        assert_eq!(words.len(), 4);
        for word in words {
            assert!(wordlist.contains(&word.to_string()));
        }
    }
}
