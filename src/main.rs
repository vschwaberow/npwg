// SPDX-License-Identifier: MIT
// Project: npwg
// File: src/main.rs
// Author: Volker Schwaberow <volker@schwaberow.de>
// Copyright (c) 2022 Volker Schwaberow

mod config;
mod diceware;
mod error;
mod generator;
mod stats;

use std::process::exit;

use crate::config::DEFINE;
use clap::{value_parser, Arg, ArgAction, Command};
use colored::*;
use config::{PasswordGeneratorConfig, PasswordGeneratorMode};
use error::{PasswordGeneratorError, Result};
use generator::{generate_diceware_passphrase, generate_passwords};
use stats::show_stats;
use zeroize::Zeroize;

#[tokio::main]
async fn main() -> Result<()> {
    let matches = Command::new("npwg")
        .version("0.2.1")
        .author("Volker Schwaberow <volker@schwaberow.de>")
        .about("Generates secure passwords")
        .arg(
            Arg::new("length")
                .short('l')
                .long("length")
                .value_name("LENGTH")
                .help("Sets the length of the password")
                .default_value("16")
                .value_parser(value_parser!(u8)),
        )
        .arg(
            Arg::new("count")
                .short('c')
                .long("count")
                .value_name("COUNT")
                .help("Sets the number of passwords to generate")
                .default_value("1")
                .value_parser(value_parser!(u32)),
        )
        .arg(
            Arg::new("avoid-repeating")
                .long("avoid-repeating")
                .help("Avoid repeating characters in the password")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("stats")
                .long("stats")
                .help("Show statistics about the generated passwords")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("allowed")
                .short('a')
                .long("allowed")
                .value_name("CHARS")
                .help("Sets the allowed characters")
                .default_value("allprint"),
        )
        .arg(
            Arg::new("use-words")
                .long("use-words")
                .help("Use words instead of characters")
                .action(ArgAction::SetTrue),
        )
        .get_matches();

    let length = *matches.get_one::<u8>("length").unwrap();
    let count = *matches.get_one::<u32>("count").unwrap();
    let avoid_repeating = matches.get_flag("avoid-repeating");
    let allowed = matches.get_one::<String>("allowed").unwrap();
    let use_words = matches.get_flag("use-words");

    let mut config = PasswordGeneratorConfig::new();
    config.length = length as usize;
    config.num_passwords = count as usize;
    config.set_avoid_repeating(avoid_repeating);
    config.clear_allowed_chars();

    let define_keys: Vec<&str> = DEFINE.iter().map(|&(key, _)| key).collect();

    for charset in allowed.split(',') {
        let charset = charset.trim();
        if DEFINE.iter().any(|&(key, _)| key == charset) {
            config.add_allowed_chars(charset);
        } else {
            eprintln!(
                "Error: Unknown characterset '{}' was ignored. Use one of: {}",
                charset.red(),
                define_keys.join(", ").green()
            );
            exit(1);
        }
    }

    config.set_use_words(use_words);

    config.validate()?;
    match config.mode {
        PasswordGeneratorMode::Diceware => {
            let wordlist = match diceware::get_wordlist().await {
                Ok(list) => list,
                Err(PasswordGeneratorError::WordlistDownloaded) => {
                    println!("Wordlist downloaded. Please run the program again.");
                    return Ok(());
                }
                Err(e) => return Err(e),
            };

            let passphrases = generate_diceware_passphrase(&wordlist, &config).await;
            for passphrase in &passphrases {
                println!("{}", passphrase.green());
            }

            if matches.get_flag("stats") {
                let pq = show_stats(&passphrases);
                println!("\n{}", "Statistics:".blue().bold());
                println!("Mean: {:.6}", pq.mean.to_string().yellow());
                println!("Variance: {:.6}", pq.variance.to_string().yellow());
                println!("Skewness: {:.6}", pq.skewness.to_string().yellow());
                println!("Kurtosis: {:.6}", pq.kurtosis.to_string().yellow());
            }
        }
        PasswordGeneratorMode::Password => {
            let passwords = generate_passwords(&config).await;
            for password in &passwords {
                println!("{}", password.green());
            }

            if matches.get_flag("stats") {
                let pq = show_stats(&passwords);
                println!("\n{}", "Statistics:".blue().bold());
                println!("Mean: {:.6}", pq.mean.to_string().yellow());
                println!("Variance: {:.6}", pq.variance.to_string().yellow());
                println!("Skewness: {:.6}", pq.skewness.to_string().yellow());
                println!("Kurtosis: {:.6}", pq.kurtosis.to_string().yellow());
            }

            passwords.into_iter().for_each(|mut p| p.zeroize());
        }
    }

    Ok(())
}
