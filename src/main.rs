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

use std::process;

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
        .version("0.2.2")
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

    let config = build_config(&matches)?;

    match config.mode {
        PasswordGeneratorMode::Diceware => handle_diceware(&config, &matches).await,
        PasswordGeneratorMode::Password => handle_password(&config, &matches).await,
    }
}

fn build_config(matches: &clap::ArgMatches) -> Result<PasswordGeneratorConfig> {
    let mut config = PasswordGeneratorConfig::new();
    config.length = *matches.get_one::<u8>("length").unwrap() as usize;
    config.num_passwords = *matches.get_one::<u32>("count").unwrap() as usize;
    config.set_avoid_repeating(matches.get_flag("avoid-repeating"));
    config.clear_allowed_chars();

    let allowed = matches.get_one::<String>("allowed").unwrap();
    for charset in allowed.split(',').map(str::trim) {
        if !DEFINE.iter().any(|&(key, _)| key == charset) {
            eprintln!(
                "Error: Unknown characterset '{}' was ignored. Use one of: {}",
                charset.red(),
                DEFINE
                    .iter()
                    .map(|&(key, _)| key)
                    .collect::<Vec<_>>()
                    .join(", ")
                    .green()
            );
            process::exit(1);
        }
        config.add_allowed_chars(charset);
    }

    config.set_use_words(matches.get_flag("use-words"));
    config.validate()?;
    Ok(config)
}

async fn handle_diceware(
    config: &PasswordGeneratorConfig,
    matches: &clap::ArgMatches,
) -> Result<()> {
    let wordlist = match diceware::get_wordlist().await {
        Ok(list) => list,
        Err(PasswordGeneratorError::WordlistDownloaded) => {
            println!("Wordlist downloaded. Please run the program again.");
            return Ok(());
        }
        Err(e) => return Err(e),
    };

    let passphrases = generate_diceware_passphrase(&wordlist, config).await;
    passphrases.iter().for_each(|p| println!("{}", p.green()));

    if matches.get_flag("stats") {
        print_stats(&passphrases);
    }

    Ok(())
}

async fn handle_password(
    config: &PasswordGeneratorConfig,
    matches: &clap::ArgMatches,
) -> Result<()> {
    let passwords = generate_passwords(config).await;
    passwords.iter().for_each(|p| println!("{}", p.green()));

    if matches.get_flag("stats") {
        print_stats(&passwords);
    }

    passwords.into_iter().for_each(|mut p| p.zeroize());
    Ok(())
}

fn print_stats(data: &[String]) {
    let pq = show_stats(data);
    println!("\n{}", "Statistics:".blue().bold());
    println!("Mean: {:.6}", pq.mean.to_string().yellow());
    println!("Variance: {:.6}", pq.variance.to_string().yellow());
    println!("Skewness: {:.6}", pq.skewness.to_string().yellow());
    println!("Kurtosis: {:.6}", pq.kurtosis.to_string().yellow());
}
