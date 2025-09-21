// SPDX-License-Identifier: MIT
// Project: npwg
// File: src/main.rs
// Author: Volker Schwaberow <volker@schwaberow.de>
// Copyright (c) 2022 Volker Schwaberow

mod config;
mod diceware;
mod error;
mod generator;
mod interactive;
mod stats;
mod strength;

const DAEMONIZE_ARG: &str = "__internal_daemonize";

use std::process;

use crate::config::DEFINE;
use arboard::Clipboard;
#[cfg(target_os = "linux")]
use arboard::SetExtLinux;
use clap::{value_parser, Arg, ArgAction, ArgGroup, Command};
use colored::*;
use config::{PasswordGeneratorConfig, PasswordGeneratorMode, Separator};
use dialoguer::Input;
use error::{PasswordGeneratorError, Result};
use generator::{
    generate_diceware_passphrase, generate_passwords, generate_pronounceable_passwords,
    mutate_password, MutationType,
};
use stats::show_stats;
use strength::{
    evaluate_password_strength, get_improvement_suggestions, get_strength_bar,
    get_strength_feedback,
};
use zeroize::Zeroize;

impl From<arboard::Error> for PasswordGeneratorError {
    fn from(error: arboard::Error) -> Self {
        PasswordGeneratorError::ClipboardError(error.to_string())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        use std::env;

        if env::args().any(|arg| arg == DAEMONIZE_ARG) {
            return copy_to_clipboard("").map(|_| ());
        }
    }
    let matches = build_cli().get_matches();

    if matches.get_flag("interactive") {
        return interactive::interactive_mode().await;
    }

    let config = build_config(&matches)?;

    let copy = matches.get_flag("copy");

    if matches.get_flag("mutate") {
        handle_mutation(&config, &matches, copy).await
    } else {
        match config.mode {
            PasswordGeneratorMode::Diceware => handle_diceware(&config, &matches, copy).await,
            PasswordGeneratorMode::Password => {
                if config.pronounceable {
                    handle_pronounceable(&config, &matches, copy).await
                } else {
                    handle_password(&config, &matches, copy).await
                }
            }
        }
    }
}

fn build_cli() -> Command {
    Command::new("npwg")
        .version(clap::crate_version!())
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
            Arg::new("strength")
                .long("strength")
                .help("Show strength meter for the generated passwords")
                .action(ArgAction::SetTrue),
        )
        .group(
            ArgGroup::new("output_options")
                .args(["stats", "strength"])
                .multiple(true),
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
        .arg(
            Arg::new("interactive")
                .short('i')
                .long("interactive")
                .help("Start interactive console mode")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("separator")
                .long("separator")
                .value_name("SEPARATOR")
                .help("Sets the separator for diceware passphrases (single character or 'random')")
                .requires("use-words"),
        )
        .arg(
            Arg::new("pronounceable")
                .long("pronounceable")
                .help("Generate pronounceable passwords")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("mutate")
                .long("mutate")
                .help("Mutate the passwords")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("mutation_type")
                .long("mutation-type")
                .help("Type of mutation to apply")
                .value_parser(value_parser!(MutationType))
                .default_value("replace"),
        )
        .arg(
            Arg::new("mutation_strength")
                .long("mutation-strength")
                .help("Strength of mutation")
                .default_value("1"),
        )
        .arg(
            Arg::new("lengthen")
                .long("lengthen")
                .value_name("INCREASE")
                .help("Increase the length of passwords during mutation")
                .value_parser(value_parser!(usize)),
        )
        .arg(
            Arg::new("copy")
                .long("copy")
                .help("Copy the generated password to the clipboard")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("pattern")
                .short('p')
                .long("pattern")
                .help("Pattern for password generation (e.g., LLDDS)")
                .value_parser(value_parser!(String)),
        )
        .group(
            ArgGroup::new("generation")
                .args([
                    "pattern",
                    "avoid-repeating",
                    "allowed",
                    "use-words",
                    "separator",
                    "pronounceable",
                    "mutate",
                    "mutation_type",
                    "mutation_strength",
                    "lengthen",
                ])
                .multiple(true)
                .required(false),
        )
        .arg(
            Arg::new("seed")
                .short('s')
                .long("seed")
                .value_name("SEED")
                .help("Sets the seed for the random number generator")
                .value_parser(value_parser!(u64)),
        )
}

fn build_config(matches: &clap::ArgMatches) -> Result<PasswordGeneratorConfig> {
    let mut config = PasswordGeneratorConfig::new();
    config.length = *matches.get_one::<u8>("length").unwrap() as usize;
    config.num_passwords = *matches.get_one::<u32>("count").unwrap() as usize;
    config.set_avoid_repeating(matches.get_flag("avoid-repeating"));
    config.seed = matches.get_one::<u64>("seed").copied();
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
    config.mode = if matches.get_flag("use-words") {
        PasswordGeneratorMode::Diceware
    } else {
        PasswordGeneratorMode::Password
    };

    config.pronounceable = matches.get_flag("pronounceable");

    if config.mode == PasswordGeneratorMode::Diceware {
        config.separator = if let Some(separator) = matches.get_one::<String>("separator") {
            match separator.as_str() {
                "random" => Some(Separator::Random(('a'..='z').chain('0'..='9').collect())),
                s if s.len() == 1 => Some(Separator::Fixed(s.chars().next().unwrap())),
                _ => {
                    eprintln!("Error: Separator must be a single character or 'random'");
                    process::exit(1);
                }
            }
        } else {
            Some(Separator::Fixed(' '))
        };
    }

    config.pattern = matches.get_one::<String>("pattern").cloned();

    config.validate()?;
    Ok(config)
}

async fn handle_diceware(
    config: &PasswordGeneratorConfig,
    matches: &clap::ArgMatches,
    copy: bool,
) -> Result<()> {
    let wordlist = match diceware::get_wordlist().await {
        Ok(list) => list,
        Err(PasswordGeneratorError::WordlistDownloaded) => {
            println!("Wordlist downloaded. Please run the program again.");
            return Ok(());
        }
        Err(e) => return Err(e),
    };

    let passphrases = generate_diceware_passphrase(&wordlist, config).await?;
    passphrases.iter().for_each(|p| println!("{}", p.green()));

    if copy && !passphrases.is_empty() {
        copy_to_clipboard(&passphrases.join("\n"))?;
        println!("{}", "Passphrase(s) copied to clipboard.".bold().green());
    }

    if matches.get_flag("strength") {
        print_strength_meter(&passphrases);
    }

    if matches.get_flag("stats") {
        print_stats(&passphrases);
    }

    Ok(())
}

async fn handle_password(
    config: &PasswordGeneratorConfig,
    matches: &clap::ArgMatches,
    copy: bool,
) -> Result<()> {
    let passwords = generate_passwords(config).await?;
    passwords.iter().for_each(|p| println!("{}", p.green()));

    if copy && !passwords.is_empty() {
        copy_to_clipboard(&passwords.join("\n"))?;
        println!("{}", "Password(s) copied to clipboard.".bold().green());
    }

    if matches.get_flag("strength") {
        print_strength_meter(&passwords);
    }

    if matches.get_flag("stats") {
        print_stats(&passwords);
    }

    passwords.into_iter().for_each(|mut p| p.zeroize());
    Ok(())
}

async fn handle_pronounceable(
    config: &PasswordGeneratorConfig,
    matches: &clap::ArgMatches,
    copy: bool,
) -> Result<()> {
    let passwords = generate_pronounceable_passwords(config).await?;
    passwords.iter().for_each(|p| println!("{}", p.green()));

    if copy && !passwords.is_empty() {
        copy_to_clipboard(&passwords.join("\n"))?;
        println!("{}", "Passphrase(s) copied to clipboard.".bold().green());
    }

    if matches.get_flag("strength") {
        print_strength_meter(&passwords);
    }

    if matches.get_flag("stats") {
        print_stats(&passwords);
    }

    passwords.into_iter().for_each(|mut p| p.zeroize());
    Ok(())
}

async fn handle_mutation(
    config: &PasswordGeneratorConfig,
    matches: &clap::ArgMatches,
    copy: bool,
) -> Result<()> {
    let passwords: Vec<String> = Input::<String>::new()
        .with_prompt("Enter passwords to mutate (comma-separated)")
        .interact_text()?
        .split(',')
        .map(|s| s.trim().to_string())
        .collect();

    let lengthen = matches.get_one::<usize>("lengthen").unwrap_or(&0);

    let cli_mutation_type_arg = matches.get_one::<MutationType>("mutation_type");

    let mutation_strength = matches.get_one::<u32>("mutation_strength").unwrap_or(&1);

    let passwords_clone = passwords.clone();

    println!("\n{}", "Mutated Passwords:".bold().green());
    for password in passwords {
        let mutated = mutate_password(
            &password,
            config,
            *lengthen,
            *mutation_strength,
            cli_mutation_type_arg,
        );
        println!("Original: {}", password.yellow());
        let mutation_type_display = cli_mutation_type_arg
            .map(|t| t.to_string())
            .unwrap_or_else(|| "random".to_string());
        println!(
            "Mutated:  {} (using {})",
            mutated.green(),
            mutation_type_display
        );
        println!();
    }

    if copy && !passwords_clone.is_empty() {
        copy_to_clipboard(&passwords_clone.join("\n"))?;
        println!("{}", "Passphrase(s) copied to clipboard.".bold().green());
    }

    if matches.get_flag("strength") {
        print_strength_meter(&passwords_clone);
    }

    if matches.get_flag("stats") {
        print_stats(&passwords_clone);
    }

    Ok(())
}

fn copy_to_clipboard(text: &str) -> Result<()> {
    ensure_clipboard_text(text)?;
    #[cfg(target_os = "linux")]
    {
        use std::env;

        if env::args().any(|arg| arg == DAEMONIZE_ARG) {
            let text = env::var("CLIPBOARD_TEXT").map_err(|_| {
                PasswordGeneratorError::ClipboardError(
                    "Failed to read CLIPBOARD_TEXT environment variable".to_string(),
                )
            })?;
            write_to_clipboard(&text)?;
            loop {
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
        } else {
            spawn_clipboard_daemon(text)?;
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        write_to_clipboard(text)?;
    }

    Ok(())
}

fn ensure_clipboard_text(text: &str) -> Result<()> {
    if text.trim().is_empty() {
        return Err(PasswordGeneratorError::ClipboardError(
            "Clipboard text is empty; nothing to copy.".to_string(),
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn spawn_clipboard_daemon(text: &str) -> Result<()> {
    use std::{env, process};

    process::Command::new(env::current_exe()?)
        .arg(DAEMONIZE_ARG)
        .stdin(process::Stdio::null())
        .stdout(process::Stdio::null())
        .stderr(process::Stdio::null())
        .env("CLIPBOARD_TEXT", text)
        .current_dir("/")
        .spawn()
        .map(|_| ())
        .map_err(|e| {
            PasswordGeneratorError::ClipboardUnavailable(format!(
                "Failed to spawn clipboard helper: {}",
                e
            ))
        })
}

#[cfg(target_os = "linux")]
fn write_to_clipboard(text: &str) -> Result<()> {
    let mut clipboard = Clipboard::new().map_err(|e| {
        PasswordGeneratorError::ClipboardUnavailable(format!(
            "Unable to access clipboard backend (install wl-clipboard?): {}",
            e
        ))
    })?;

    clipboard.set().wait().text(text.to_string()).map_err(|e| {
        PasswordGeneratorError::ClipboardError(format!("Failed to write text to clipboard: {}", e))
    })?;

    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn write_to_clipboard(text: &str) -> Result<()> {
    let mut clipboard = Clipboard::new().map_err(|e| {
        PasswordGeneratorError::ClipboardUnavailable(format!("Unable to access clipboard: {}", e))
    })?;

    clipboard.set_text(text.to_owned()).map_err(|e| {
        PasswordGeneratorError::ClipboardError(format!("Failed to write text to clipboard: {}", e))
    })?;

    Ok(())
}

#[cfg(test)]
fn copy_to_clipboard_with<F>(text: &str, mut setter: F) -> Result<()>
where
    F: FnMut(&str) -> Result<()>,
{
    ensure_clipboard_text(text)?;
    setter(text)
}

fn print_strength_meter(data: &[String]) {
    println!("\n{}", "Password Strength:".blue().bold());
    for (i, password) in data.iter().enumerate() {
        let strength = evaluate_password_strength(password);
        let feedback = get_strength_feedback(strength);
        let strength_bar = get_strength_bar(strength);
        println!(
            "Password {}: {} {:.2} {} {}",
            i + 1,
            strength_bar,
            strength,
            feedback.color(match &*feedback {
                "Very Weak" => "red",
                "Weak" => "yellow",
                "Moderate" => "blue",
                "Strong" => "green",
                "Very Strong" => "bright green",
                _ => "white",
            }),
            password.yellow()
        );

        if strength < 0.6 {
            let suggestions = get_improvement_suggestions(password);
            if !suggestions.is_empty() {
                println!("  {}:", "Improvement suggestions".cyan());
                for suggestion in suggestions {
                    println!("   • {}", suggestion);
                }
            }
        }
    }
}

fn print_stats(data: &[String]) {
    let pq = show_stats(data);
    println!("\n{}", "Statistics:".blue().bold());
    println!("Mean: {:.6}", pq.mean.to_string().yellow());
    println!("Variance: {:.6}", pq.variance.to_string().yellow());
    println!("Skewness: {:.6}", pq.skewness.to_string().yellow());
    println!("Kurtosis: {:.6}", pq.kurtosis.to_string().yellow());
}

#[cfg(test)]
mod cli_tests {
    use super::*;

    #[test]
    fn test_cli_parses_pattern_and_seed() {
        let matches = build_cli()
            .try_get_matches_from([
                "npwg",
                "--pattern",
                "LLDDS",
                "--allowed",
                "lowerletter",
                "--length",
                "10",
                "--seed",
                "99",
            ])
            .unwrap();
        let config = build_config(&matches).unwrap();
        assert_eq!(config.pattern.as_deref(), Some("LLDDS"));
        assert_eq!(config.length, 10);
        assert_eq!(config.seed, Some(99));
    }

    #[test]
    fn test_cli_pronounceable_flag_sets_mode() {
        let matches = build_cli()
            .try_get_matches_from(["npwg", "--pronounceable", "--allowed", "lowerletter"])
            .unwrap();
        let config = build_config(&matches).unwrap();
        assert!(config.pronounceable);
        assert!(matches.get_flag("pronounceable"));
    }

    #[test]
    fn test_copy_to_clipboard_with_failure_path() {
        let error = copy_to_clipboard_with("secret", |_| {
            Err(PasswordGeneratorError::ClipboardUnavailable(
                "backend missing".to_string(),
            ))
        })
        .unwrap_err();
        match error {
            PasswordGeneratorError::ClipboardUnavailable(message) => {
                assert!(message.contains("backend"));
            }
            other => panic!("Unexpected error variant: {:?}", other),
        }
    }

    #[test]
    fn test_copy_to_clipboard_rejects_empty_text() {
        let error = copy_to_clipboard_with("   ", |_| Ok(())).unwrap_err();
        match error {
            PasswordGeneratorError::ClipboardError(message) => {
                assert!(message.contains("empty"));
            }
            other => panic!("Unexpected error variant: {:?}", other),
        }
    }
}
