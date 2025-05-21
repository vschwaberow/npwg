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

    #[test]
    fn test_show_stats_single_password() {
        let passwords = vec!["password123".to_string()];
        let stats = show_stats(&passwords);
        assert_eq!(stats.variance, 0.0, "Variance should be 0.0 for a single password");
        assert_eq!(stats.skewness, 0.0, "Skewness should be 0.0 for a single password");
        assert_eq!(stats.kurtosis, -3.0, "Kurtosis should be -3.0 for a single password (excess kurtosis)");
    }

    #[test]
    fn test_show_stats_identical_passwords() {
        let passwords = vec!["password123".to_string(), "password123".to_string(), "password123".to_string()];
        let stats = show_stats(&passwords);
        assert_eq!(stats.variance, 0.0, "Variance should be 0.0 for identical passwords");
        assert_eq!(stats.skewness, 0.0, "Skewness should be 0.0 for identical passwords");
        assert_eq!(stats.kurtosis, -3.0, "Kurtosis should be -3.0 for identical passwords (excess kurtosis)");
    }

    #[test]
    fn test_show_stats_different_passwords() {
        let passwords = vec!["password123".to_string(), "anotherOne".to_string(), "testPwd!".to_string()];
        let stats = show_stats(&passwords);
        assert!(stats.variance > 0.0, "Variance should be greater than 0 for different passwords");
        assert!(stats.skewness.is_finite(), "Skewness should be a finite number");
        assert!(stats.kurtosis.is_finite(), "Kurtosis should be a finite number");
    }

    #[test]
    fn test_show_stats_empty_list() {
        let passwords: Vec<String> = Vec::new();
        let stats = show_stats(&passwords);
        assert_eq!(stats.mean, 0.0, "Mean should be 0.0 for an empty list");
        assert_eq!(stats.variance, 0.0, "Variance should be 0.0 for an empty list");
        assert_eq!(stats.skewness, 0.0, "Skewness should be 0.0 for an empty list");
        assert_eq!(stats.kurtosis, 0.0, "Kurtosis should be 0.0 for an empty list");
    }

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

    #[test]
    fn test_show_stats_single_password() {
        let passwords = vec!["password123".to_string()];
        let stats = show_stats(&passwords);
        assert_eq!(stats.variance, 0.0, "Variance should be 0.0 for a single password");
        assert_eq!(stats.skewness, 0.0, "Skewness should be 0.0 for a single password");
        assert_eq!(stats.kurtosis, -3.0, "Kurtosis should be -3.0 for a single password (excess kurtosis)");
    }

    #[test]
    fn test_show_stats_identical_passwords() {
        let passwords = vec!["password123".to_string(), "password123".to_string(), "password123".to_string()];
        let stats = show_stats(&passwords);
        assert_eq!(stats.variance, 0.0, "Variance should be 0.0 for identical passwords");
        assert_eq!(stats.skewness, 0.0, "Skewness should be 0.0 for identical passwords");
        assert_eq!(stats.kurtosis, -3.0, "Kurtosis should be -3.0 for identical passwords (excess kurtosis)");
    }

    #[test]
    fn test_show_stats_different_passwords() {
        let passwords = vec!["password123".to_string(), "anotherOne".to_string(), "testPwd!".to_string()];
        let stats = show_stats(&passwords);
        assert!(stats.variance > 0.0, "Variance should be greater than 0 for different passwords");
        assert!(stats.skewness.is_finite(), "Skewness should be a finite number");
        assert!(stats.kurtosis.is_finite(), "Kurtosis should be a finite number");
    }

    #[test]
    fn test_show_stats_empty_list() {
        let passwords: Vec<String> = Vec::new();
        let stats = show_stats(&passwords);
        assert_eq!(stats.mean, 0.0, "Mean should be 0.0 for an empty list");
        assert_eq!(stats.variance, 0.0, "Variance should be 0.0 for an empty list");
        assert_eq!(stats.skewness, 0.0, "Skewness should be 0.0 for an empty list");
        assert_eq!(stats.kurtosis, 0.0, "Kurtosis should be 0.0 for an empty list");
    }
}
