// SPDX-License-Identifier: MIT
// Project: npwg
// File: src/tests.rs
// Author: Volker Schwaberow <volker@schwaberow.de>
// Copyright (c) 2022 Volker Schwaberow

#[cfg(test)]
mod tests {
    use crate::config::PasswordGeneratorConfig;
    use crate::error::PasswordGeneratorError;
    use crate::generator::{generate_diceware_passphrase, generate_password};
    use crate::generator::{generate_pronounceable_password, mutate_password, MutationType};
    use crate::stats::show_stats;

    async fn generate_diceware_passphrase_test(wordlist: &[String], num_words: usize) -> String {
        let mut config = PasswordGeneratorConfig::new();
        config.length = num_words;
        config.mode = crate::config::PasswordGeneratorMode::Diceware;
        let results = generate_diceware_passphrase(wordlist, &config)
            .await
            .unwrap();
        results.into_iter().next().unwrap_or_default()
    }

    #[tokio::test]
    async fn test_password_generator_config_new() {
        let mut config = PasswordGeneratorConfig::new();
        config.set_allowed_chars("allprint");
        assert_eq!(config.length, 16);
        assert_eq!(config.allowed_chars.len(), 94);
        assert!(config.excluded_chars.is_empty());
        assert!(config.included_chars.is_empty());
        assert_eq!(config.num_passwords, 1);
    }

    #[test]
    fn test_password_generator_config_validate() {
        let mut config = PasswordGeneratorConfig::new();
        config.set_allowed_chars("allprint");
        assert!(config.validate().is_ok());

        config.allowed_chars.clear();
        assert!(config.validate().is_err());
    }

    #[tokio::test]
    async fn test_generate_password() {
        let mut config = PasswordGeneratorConfig::new();
        config.set_allowed_chars("allprint");
        let password = generate_password(&config).await.unwrap();
        assert_eq!(password.len(), 16);
    }

    #[tokio::test]
    async fn test_generate_pronounceable_password_pattern() {
        let mut config = PasswordGeneratorConfig::new();
        config.pronounceable = true;
        config.length = 8;
        let password = generate_pronounceable_password(&config).await.unwrap();
        assert_eq!(password.len(), 8);
        let consonants = "bcdfghjklmnpqrstvwxyz";
        let vowels = "aeiou";
        for (idx, ch) in password.chars().enumerate() {
            if idx % 2 == 0 {
                assert!(consonants.contains(ch));
            } else {
                assert!(vowels.contains(ch));
            }
        }
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

        // Check if we have received a passphrase with words
        assert!(!passphrase.is_empty(), "Passphrase should not be empty");

        // We need to check if the words from our original list are present
        // rather than counting words in the output, since separators might vary
        for word in &wordlist {
            if passphrase.contains(word) {
                // If at least one word is found, the test is successful
                return;
            }
        }

        panic!("Passphrase does not contain any words from the wordlist");
    }

    #[test]
    fn test_show_stats_single_password() {
        let passwords = vec!["password123".to_string()];
        let stats = show_stats(&passwords);
        assert_eq!(
            stats.variance, 0.0,
            "Variance should be 0.0 for a single password"
        );
        assert_eq!(
            stats.skewness, 0.0,
            "Skewness should be 0.0 for a single password"
        );
        assert_eq!(
            stats.kurtosis, -3.0,
            "Kurtosis should be -3.0 for a single password (excess kurtosis)"
        );
    }

    #[test]
    fn test_show_stats_identical_passwords() {
        let passwords = vec![
            "password123".to_string(),
            "password123".to_string(),
            "password123".to_string(),
        ];
        let stats = show_stats(&passwords);
        assert!(
            stats.variance.abs() < 1e-10,
            "Variance should be approximately 0.0 for identical passwords"
        );
        assert!(
            stats.skewness.is_finite(),
            "Skewness should be finite for identical passwords"
        );
        assert_eq!(
            stats.kurtosis, -3.0,
            "Kurtosis should be -3.0 for identical passwords (excess kurtosis)"
        );
    }

    #[test]
    fn test_show_stats_different_passwords() {
        let passwords = vec![
            "password123".to_string(),
            "anotherOne".to_string(),
            "testPwd!".to_string(),
        ];
        let stats = show_stats(&passwords);
        assert!(
            stats.variance > 0.0,
            "Variance should be greater than 0 for different passwords"
        );
        assert!(
            stats.skewness.is_finite(),
            "Skewness should be a finite number"
        );
        assert!(
            stats.kurtosis.is_finite(),
            "Kurtosis should be a finite number"
        );
    }

    #[test]
    fn test_show_stats_empty_list() {
        let passwords: Vec<String> = Vec::new();
        let stats = show_stats(&passwords);
        assert_eq!(stats.mean, 0.0, "Mean should be 0.0 for an empty list");
        assert_eq!(
            stats.variance, 0.0,
            "Variance should be 0.0 for an empty list"
        );
        assert_eq!(
            stats.skewness, 0.0,
            "Skewness should be 0.0 for an empty list"
        );
        assert_eq!(
            stats.kurtosis, 0.0,
            "Kurtosis should be 0.0 for an empty list"
        );
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
        assert!(
            result.is_err(),
            "Expected error when all chars are excluded"
        );

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

    #[test]
    fn test_mutate_password_replace_changes_character() {
        let mut config = PasswordGeneratorConfig::new();
        config.set_allowed_chars("lowerletter");
        config.seed = Some(42);
        let forced = MutationType::Replace;
        let original = "password";
        let mutated = mutate_password(original, &config, 0, 1, Some(&forced));
        assert_eq!(mutated.len(), original.len());
        assert_ne!(mutated, original);
    }

    #[test]
    fn test_mutate_password_lengthen_appends_characters() {
        let mut config = PasswordGeneratorConfig::new();
        config.set_allowed_chars("digit");
        config.seed = Some(7);
        let original = "1234";
        let mutated = mutate_password(original, &config, 3, 0, None);
        assert_eq!(mutated.len(), original.len() + 3);
        assert!(mutated.starts_with(original));
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
        assert_eq!(
            get_theoretical_char_set_size("aA1!€"),
            26 + 26 + 10 + 32 + 1
        );
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
        assert!(
            (score - 0.18).abs() < 0.001,
            "Expected approx 0.18, got {}",
            score
        );
    }

    #[test]
    fn test_calc_entropy_single_char_type_all_diff() {
        let score = calculate_entropy("abc");
        assert!(
            (score - 0.378).abs() < 0.001,
            "Expected approx 0.378, got {}",
            score
        );
    }

    #[test]
    fn test_calc_entropy_two_char_types_perfect_mix() {
        let score = calculate_entropy("a1b2");
        assert!(
            (score - 0.4337).abs() < 0.001,
            "Expected approx 0.4337, got {}",
            score
        );
    }

    #[test]
    fn test_calc_entropy_only_other_unique() {
        let score = calculate_entropy("€α");
        assert!(
            (score - 0.83).abs() < 0.05,
            "Expected approx 0.83, got {}",
            score
        );
    }
}

#[cfg(test)]
mod pattern_tests {
    use crate::generator::generate_with_pattern;

    #[test]
    fn test_generate_with_pattern_skip_unfulfillable_chars() {
        let available_chars: Vec<char> = "abcdefg".chars().collect();
        let pattern = "LDLS";
        let length = 10;
        let seed = None;

        let result = generate_with_pattern(pattern, &available_chars, length, seed);
        assert!(
            result.is_ok(),
            "Expected successful generation despite unfulfillable pattern"
        );

        let password = result.unwrap();
        assert_eq!(
            password.len(),
            length,
            "Password should match the requested length"
        );

        for c in password.chars() {
            assert!(
                available_chars.contains(&c),
                "Password contains character not in available_chars: {}",
                c
            );
        }

        assert!(
            !password.chars().any(|c| c.is_ascii_digit()),
            "Password should not contain digits"
        );
    }
}
