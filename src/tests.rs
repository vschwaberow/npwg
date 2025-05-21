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
    
    async fn generate_diceware_passphrase_test(wordlist: &[String], num_words: usize) -> String {
        let mut config = PasswordGeneratorConfig::new();
        config.length = num_words;
        let results = generate_diceware_passphrase(wordlist, &config).await.unwrap();
        results.into_iter().next().unwrap_or_default()
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
        let password = generate_password(&config).await.unwrap();
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

        let passphrase = generate_diceware_passphrase_test(&wordlist, 4).await;

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
        let password = generate_password(&config).await.unwrap();
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

        let passphrase = generate_diceware_passphrase_test(&wordlist, 4).await;

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
    async fn test_generate_password_with_empty_available_chars() {
        let mut config = PasswordGeneratorConfig::new();
        config.clear_allowed_chars();
        
        let result = generate_password(&config).await;
        assert!(result.is_err(), "Expected error for empty available_chars");
        
        if let Err(err) = result {
            match err {
                PasswordGeneratorError::InvalidConfig(_) => {
                    assert!(true);
                }
                _ => {
                    panic!("Expected InvalidConfig error, got {:?}", err);
                }
            }
        }
    }

    #[tokio::test]
    async fn test_generate_password_with_all_chars_excluded() {
        let mut config = PasswordGeneratorConfig::new();
        config.set_allowed_chars("digit");        
        config.excluded_chars.extend("0123456789".chars());
        let result = generate_password(&config).await;
        assert!(result.is_err(), "Expected error when all chars are excluded");
        
        if let Err(err) = result {
            match err {
                PasswordGeneratorError::InvalidConfig(_) => {
                    assert!(true);
                }
                _ => {
                    panic!("Expected InvalidConfig error, got {:?}", err);
                }
            }
        }
    }
}

#[cfg(test)]
mod strength_tests {
    use crate::strength::{calculate_entropy, get_theoretical_char_set_size};

    #[test]
    fn test_gcss_empty() {
        assert_eq!(get_theoretical_char_set_size(""), 0);
    }

    #[test]
    fn test_gcss_lowercase_only() {
        assert_eq!(get_theoretical_char_set_size("abc"), 26);
        assert_eq!(get_theoretical_char_set_size("aaaaa"), 26);
    }

    #[test]
    fn test_gcss_uppercase_only() {
        assert_eq!(get_theoretical_char_set_size("ABC"), 26);
    }

    #[test]
    fn test_gcss_digits_only() {
        assert_eq!(get_theoretical_char_set_size("123"), 10);
    }

    #[test]
    fn test_gcss_punctuation_only() {
        assert_eq!(get_theoretical_char_set_size("!@#"), 32); 
        assert_eq!(get_theoretical_char_set_size("!!!"), 32);
    }

    #[test]
    fn test_gcss_lowercase_uppercase() {
        assert_eq!(get_theoretical_char_set_size("aB"), 26 + 26);
    }

    #[test]
    fn test_gcss_lower_digits() {
        assert_eq!(get_theoretical_char_set_size("a1"), 26 + 10);
    }

    #[test]
    fn test_gcss_lower_punct() {
        assert_eq!(get_theoretical_char_set_size("a!"), 26 + 32);
    }

    #[test]
    fn test_gcss_all_standard_types() {
        assert_eq!(get_theoretical_char_set_size("aA1!"), 26 + 26 + 10 + 32);
    }

    #[test]
    fn test_gcss_only_other_unique() {
        assert_eq!(get_theoretical_char_set_size("€αβ"), 3);
    }

    #[test]
    fn test_gcss_only_other_repeated() {
        assert_eq!(get_theoretical_char_set_size("€€€"), 1);
    }
    
    #[test]
    fn test_gcss_known_and_other_unique() {
        assert_eq!(get_theoretical_char_set_size("abcαβ"), 26 + 2); 
    }

    #[test]
    fn test_gcss_known_and_other_mixed() {
        assert_eq!(get_theoretical_char_set_size("aA1!€"), 26 + 26 + 10 + 32 + 1);
    }
    
    #[test]
    fn test_gcss_space_only() { 
        assert_eq!(get_theoretical_char_set_size(" "), 1);
        assert_eq!(get_theoretical_char_set_size("   "), 1);
    }

    #[test]
    fn test_gcss_space_and_letter() { 
        assert_eq!(get_theoretical_char_set_size("a b"), 26 + 1);
    }

    #[test]
    fn test_calc_entropy_empty() {
        assert_eq!(calculate_entropy(""), 0.0);
    }

    #[test]
    fn test_calc_entropy_single_char_type_all_same() {
        let score = calculate_entropy("aaaaa");
        assert!((score - 0.18).abs() < 0.001, "Expected approx 0.18, got {}", score);
    }

    #[test]
    fn test_calc_entropy_single_char_type_all_diff() {
        let score = calculate_entropy("abc");
        assert!((score - 0.378).abs() < 0.001, "Expected approx 0.378, got {}", score);
    }

    #[test]
    fn test_calc_entropy_two_char_types_perfect_mix() {
        let score = calculate_entropy("a1b2");
        assert!((score - 0.4337).abs() < 0.001, "Expected approx 0.4337, got {}", score);
    }

    #[test]
    fn test_calc_entropy_only_other_unique() {
        let score = calculate_entropy("€α");
         assert!((score - 0.8125).abs() < 0.001, "Expected approx 0.8125, got {}", score);
    }
}
