// SPDX-License-Identifier: MIT
// Project: npwg
// File: main.rs
// Author: Volker Schwaberow <volker@schwaberow.de>
// Copyright (c) 2022 Volker Schwaberow

use clap::{arg, command, value_parser};
use rand::rngs::SmallRng;
use rand::{Rng, SeedableRng};
use rand_distr::Distribution as StatisticsDistribution;
use rand_distr::Normal;
use std::collections::HashSet;
use zeroize::Zeroize;

/// The character sets used to generate the passwords.
/// The first element of each tuple is the name of the character set,
/// The homoglyphs are characters that look similar to other characters.
/// For example, the character 'l' looks similar to the character '1'.
/// The homoglyphs are used to avoid confusion between similar characters.
const DEFINE: &[(&str, &str)] = &[
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

/// Configuration for the password generator.
#[derive(Debug, Clone)]
struct PasswordGeneratorConfig {
    length: usize,                 // The length of the generated passwords.
    allowed_chars: Vec<char>,      // The characters allowed in the generated passwords.
    excluded_chars: HashSet<char>, // The characters to exclude from the generated passwords.
    included_chars: HashSet<char>, // The characters to include in the generated passwords.
    num_passwords: usize,          // The number of passwords to generate.
    avoid_repetition: bool,        // Avoid repetition of characters in the generated passwords.
}

/// Statistics about the generated passwords.
#[derive(Debug)]
struct PasswordQuality {
    mean: f64,     // The mean of the generated passwords.
    variance: f64, // The variance of the generated passwords.
    skewness: f64, // The skewness of the generated passwords.
    kurtosis: f64, // The kurtosis of the generated passwords.
}

/// Implementation of the `PasswordGeneratorConfig` struct.
impl PasswordGeneratorConfig {
    /// Creates a new instance of `PasswordGeneratorConfig` with default values.
    /// # Returns
    /// A new instance of `PasswordGeneratorConfig` with default values.
    fn new() -> Self {
        // Create a vector of allowed characters by filtering the character sets
        let allowed_chars: Vec<char> = DEFINE
            .iter()
            .filter(|(_, v)| {
                ["digit", "lowerletter", "upperletter", "symbol1", "symbol2"].contains(&v.as_ref())
            })
            .flat_map(|(_, chars)| chars.chars())
            .collect();

        // Return a new instance of PasswordGeneratorConfig with the default values.
        PasswordGeneratorConfig {
            length: 8,
            allowed_chars,
            excluded_chars: HashSet::new(),
            included_chars: HashSet::new(),
            num_passwords: 1,
            avoid_repetition: false,
        }
    }

    /// Validates the configuration.
    /// # Arguments
    /// * `self` - The configuration to validate.
    /// # Returns
    /// A `Result` indicating success or failure.
    fn validate(&mut self) -> Result<(), &'static str> {
        // Check if self.allowed_chars is empty
        if self.allowed_chars.is_empty() {
            return Err("allowed_chars set cannot be empty");
        }
        Ok(())
    }

    fn set_allowed_chars_default(&mut self) {
        // fill allowed_chars with the
        self.allowed_chars = "digit,lowerletter,upperletter,symbol1,symbol2"
            .chars()
            .collect();
    }
}

/// Generates a password based on the given configuration.
///
/// # Arguments
/// * `config` - The configuration for generating the password.
///
/// # Returns
/// The generated password as a string.
async fn generate_password(config: &PasswordGeneratorConfig) -> String {
    // Create a random number generator.
    let mut rng = rand::rngs::OsRng;
    // Create a string to store the generated password.
    let mut password = String::with_capacity(config.length);
    // Create a variable to store the previous character.
    let mut prev_character = None;

    // Generate a password with the specified length.
    while password.len() < config.length {
        // Generate a random character from the allowed characters.
        let candidate_char = config.allowed_chars[rng.gen_range(0..config.allowed_chars.len())];
        // Check if the character is not in the excluded characters and is in the included characters.
        if !config.excluded_chars.contains(&candidate_char)
            // Check if the included characters are empty or the character is in the included characters.
            && (config.included_chars.is_empty() || config.included_chars.contains(&candidate_char))
            && (!config.avoid_repetition || prev_character != Some(candidate_char))
        {
            // Add the character to the password.
            password.push(candidate_char);
            // Update the previous character.
            prev_character = Some(candidate_char);
        }
    }
    // Return the generated password.
    password
}

/// Shows statistics about the generated passwords.
/// # Arguments
/// * `passwords` - The generated passwords.
/// # Returns
/// The statistics about the generated passwords in the form of a `PasswordQuality` struct.
async fn show_stats(passwords: &[String]) -> PasswordQuality {
    // Create a random number generator.
    let mut rng = SmallRng::seed_from_u64(42);
    // Create a vector to store the values of the characters in the passwords.
    let mut values = Vec::with_capacity(passwords.len() * passwords[0].len());
    // Iterate over the generated passwords.
    for password in passwords {
        // Iterate over the characters in the password.
        for c in password.chars() {
            // Add the value of the character to the vector.
            values.push(c as u8 as f64);
        }
    }

    // Create a normal distribution with mean 0 and standard deviation 1.
    let distribution = Normal::new(0.0, 1.0).unwrap();

    // Generate statistics based on the values of the characters in the passwords.
    let statistics = values
        .iter()
        .map(|&x| distribution.sample(&mut rng) * x)
        .collect::<Vec<_>>();

    // Calculate the mean, variance, skewness, and kurtosis of the statistics.
    let mean = statistics.iter().sum::<f64>() / statistics.len() as f64;

    // Calculate the variance, skewness, and kurtosis of the statistics.
    let variance =
        statistics.iter().map(|&x| (x - mean).powi(2)).sum::<f64>() / statistics.len() as f64;
    let skewness = statistics.iter().map(|&x| (x - mean).powi(3)).sum::<f64>()
        / (statistics.len() as f64 * statistics.iter().map(|&x| (x - mean).powi(2)).sum::<f64>())
            .sqrt()
            .powi(3);
    let kurtosis = statistics.iter().map(|&x| (x - mean).powi(4)).sum::<f64>()
        / (statistics.len() as f64 * statistics.iter().map(|&x| (x - mean).powi(2)).sum::<f64>())
            .sqrt()
            .powi(4);

    // Return the statistics as a `PasswordQuality` struct.
    PasswordQuality {
        mean,
        variance,
        skewness,
        kurtosis,
    }
}

/// Generates the specified number of passwords based on the given configuration.
/// # Arguments
/// * `config` - The configuration for generating the passwords.
/// # Returns
/// The generated passwords as a vector of strings.
async fn generate_passwords(config: &PasswordGeneratorConfig) -> Vec<String> {
    // Create a vector to store the generated passwords.
    let mut passwords = Vec::with_capacity(config.num_passwords);
    // Generate the specified number of passwords.
    for _ in 0..config.num_passwords {
        // Generate a password and add it to the vector.
        passwords.push(generate_password(config).await);
    }
    // Return the generated passwords.
    passwords
}

/// The main function that parses the command-line arguments and generates the passwords.
/// # Arguments
/// * `args` - The command-line arguments.
/// # Returns
/// The generated passwords as a string.
#[tokio::main]
async fn main() {
    // Define the possible values for the 'allowed' argument.
    let mut parser = Vec::new();

    // Add the possible values to the parser.
    for (name, _) in DEFINE {
        parser.push(name);
    }

    // Parse the command-line arguments.
    let matches = command!()
        .about(
            "Secure password generator\nWritten 2024 by Volker Schwaberow <volker@schwaberow.de>",
        )
        .arg(arg!(-l --length <usize> "Password length (default: 8)").default_value("8"))
        .arg(
            arg!(-a --allowed <STRING> "Allowed character sets (comma-separated)")
                .required(false)
                .default_value("digit,lowerletter,upperletter,symbol1,symbol2"), //             .value_parser(parser),
        )
        .arg(arg!(-e --exclude <STRING> "Excluded characters (comma-separated)").required(false))
        .arg(arg!(-i --include <STRING> "Included characters (comma-separated)").required(false))
        .arg(
            arg!(-n --num <usize> "Number of passwords to generate (default: 1)")
                .value_parser(value_parser!(usize))
                .default_value("1"),
        )
        .arg(
            arg!(-s --stats "Print statistics about the generated passwords")
                .required(false)
                .default_value("false"),
        )
        .arg(
            arg!(-r --"avoid-repeating" "Avoid repeating characters in the generated passwords")
                .required(false)
                .default_value("false"),
        )
        .get_matches();

    // Create a new configuration with the specified values.
    let mut config = PasswordGeneratorConfig::new();

    // Update the configuration with the specified values.
    if let Some(length_str) = matches.get_one::<String>("length") {
        if let Ok(length) = length_str.parse::<usize>() {
            config.length = length;
        } else {
            eprintln!("Error: Invalid value for 'length'. It should be a positive integer.");
            return;
        }
    }
    // Update the configuration with the specified values.
    if let Some(allowed) = matches.get_one::<String>("allowed") {
        config.set_allowed_chars_default();
        config.allowed_chars = allowed
            .split(',')
            .map(|s| s.trim())
            .flat_map(|set| {
                DEFINE
                    .iter()
                    .find(|(name, _)| name == &set)
                    .unwrap_or_else(|| {
                        eprintln!(
                            "Error: Invalid value for 'allowed'. Possible values are: {:?}",
                            parser
                        );
                        std::process::exit(1);
                    })
                    .1
                    .chars()
            })
            .collect();
    } else {
        // If the 'allowed' argument is not specified, print an error message and exit.
        eprintln!("Error: possible values for 'allowed' are: {:?}", parser);
    }

    // Update the configuration with the specified values.
    if let Some(exclude) = matches.get_one::<String>("exclude") {
        // Update the configuration with the specified excluded characters.
        config.excluded_chars = exclude
            .split(',')
            .map(|c| c.trim().chars())
            .flatten()
            .collect();
    }

    // Update the configuration with the specified values.
    if let Some(include) = matches.get_one::<String>("include") {
        // Update the configuration with the specified included characters.
        config.included_chars = include
            .split(',')
            .map(|c| c.trim().chars())
            .flatten()
            .collect();
    }

    // Update the configuration with the specified values.
    if let Some(num_passwords) = matches.get_one::<usize>("num") {
        // Update the configuration with the specified number of passwords.
        config.num_passwords = *num_passwords;
    }

    // Update the configuration with the specified values.
    if let Some(avoid_repetition) = matches.get_one::<bool>("avoid-repeating") {
        // Update the configuration with the specified value for avoiding repetition.
        config.avoid_repetition = *avoid_repetition;
    }

    // Validate the configuration.
    config.validate().unwrap_or_else(|err| {
        // Print an error message and exit if the configuration is invalid.
        eprintln!("Error: {}", err);
        std::process::exit(1);
    });

    // Generate the passwords based on the configuration.
    let mut passwords = generate_passwords(&config).await;

    // Iterate over the generated passwords.
    for (_i, password) in passwords.iter().enumerate() {
        // Print the generated password.
        println!("{}", password);
    }
    // If the 'stats' argument is specified, show statistics about the generated passwords.
    if let Some(stats) = matches.get_one::<bool>("stats") {
        // Check if the 'stats' argument is set to true.
        if *stats {
            // Call the function to calculate the statistics of the generated passwords.
            let pq = show_stats(&passwords).await;
            // Print the statistics.
            println!();
            println!("Statistics:");
            println!("Mean: {}", pq.mean);
            println!("Variance: {}", pq.variance);
            println!("Skewness: {}", pq.skewness);
            println!("Kurtosis: {}", pq.kurtosis);
        }
    }
    passwords.zeroize();
}

/// Tests for the password generator.
#[cfg(test)]
mod tests {
    use super::*;

    /// Test the `PasswordGeneratorConfig::new` function.
    /// The test creates a new configuration and checks if the default values are set correctly.
    /// The test then sets the allowed characters to the default values and checks if the allowed
    /// characters are set correctly.
    #[test]
    fn test_password_generator_config_new() {
        let mut config = PasswordGeneratorConfig::new();
        config.set_allowed_chars_default();
        assert_eq!(config.length, 8);
        assert_eq!(config.allowed_chars.len(), 45);
        assert!(config.excluded_chars.is_empty());
        assert!(config.included_chars.is_empty());
        assert_eq!(config.num_passwords, 1);
    }

    /// Test the `PasswordGeneratorConfig::validate` function.
    /// The test creates a configuration with valid values and checks if the validation passes.
    /// The test then creates a configuration with invalid values and checks if the validation fails.
    /// The test checks if the validation passes for the default configuration.
    #[test]
    fn test_password_generator_config_validate() {
        let mut config = PasswordGeneratorConfig::new();
        config.set_allowed_chars_default();
        assert!(config.validate().is_ok());

        config.allowed_chars.clear();
        assert!(config.validate().is_err());
    }

    /// Test the `generate_password` function.
    /// The test generates a password and checks if the length of the generated password
    /// is equal to the length specified in the configuration.
    #[tokio::test]
    async fn test_generate_password() {
        let mut config = PasswordGeneratorConfig::new();
        config.set_allowed_chars_default();
        let password = generate_password(&config).await;
        assert_eq!(password.len(), 8);
    }

    /// Test the `generate_passwords` function.
    /// The test generates a list of passwords and checks if the number of generated passwords
    /// is equal to the number of passwords specified in the configuration.
    /// The test also checks if the length of each generated password is equal to the length
    /// specified in the configuration.
    #[tokio::test]
    async fn test_generate_passwords() {
        let mut config = PasswordGeneratorConfig::new();
        config.set_allowed_chars_default();
        let passwords = generate_passwords(&config).await;
        assert_eq!(passwords.len(), 1);
        assert_eq!(passwords[0].len(), 8);
    }

    /// Test the `show_stats` function.
    /// The test generates a list of passwords and then calls the `show_stats` function
    /// to calculate the statistics of the generated passwords.
    /// The test checks if the statistics are finite and close to the expected values.
    #[tokio::test]
    async fn test_show_stats() {
        let passwords = vec![
            "password1".to_string(),
            "password2".to_string(),
            "password3".to_string(),
        ];

        // Call the function and check if it runs successfully
        let pq = show_stats(&passwords).await;

        // Check if the statistics are finite
        assert!(pq.mean.is_finite());
        assert!(pq.variance.is_finite());
        assert!(pq.skewness.is_finite());
        assert!(pq.kurtosis.is_finite());

        // Check if the statistics are close to the expected values
        assert!((pq.mean + 23.55712741349045).abs() < 1e-10);
        assert!((pq.variance - 9848.07488561167).abs() < 1e-10);
        assert!((pq.skewness - 0.0004527807986432392).abs() < 1e-10);
        assert!((pq.kurtosis - 0.00017329344204029657).abs() < 1e-10);
    }
}
