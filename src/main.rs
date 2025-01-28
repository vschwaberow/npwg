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
use console::Term;
use dialoguer::{theme::ColorfulTheme, Confirm, Input, Select};
use error::{PasswordGeneratorError, Result};
use generator::{
    generate_diceware_passphrase, generate_passwords, generate_pronounceable_passwords,
    mutate_password, MutationType,
};
use stats::show_stats;
use strength::{evaluate_password_strength, get_strength_bar, get_strength_feedback};
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
    let matches = Command::new("npwg")
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
                .args(["pattern", "avoid-repeating", "allowed", "use-words", "separator", "pronounceable", "mutate", "mutation_type", "mutation_strength", "lengthen"])
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
        .get_matches();

    if matches.get_flag("interactive") {
        return interactive_mode().await;
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

    let passphrases = generate_diceware_passphrase(&wordlist, config).await;
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
    let passwords = generate_passwords(config).await;
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
    let passwords = generate_pronounceable_passwords(config).await;
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

    let mutation_type = matches
        .get_one::<MutationType>("mutation_type")
        .unwrap_or(&MutationType::Replace);

    let mutation_strength = matches.get_one::<u32>("mutation_strength").unwrap_or(&1);

    let passwords_clone = passwords.clone();

    println!("\n{}", "Mutated Passwords:".bold().green());
    for password in passwords {
        let mutated = mutate_password(&password, config, *lengthen, *mutation_strength);
        println!("Original: {}", password.yellow());
        println!("Mutated:  {} (using {})", mutated.green(), mutation_type);
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
    #[cfg(target_os = "linux")]
    {
        use std::{env, process};

        if env::args().any(|arg| arg == DAEMONIZE_ARG) {
            let text = env::var("CLIPBOARD_TEXT").map_err(|_| {
                PasswordGeneratorError::ClipboardError(
                    "Failed to read CLIPBOARD_TEXT environment variable".to_string(),
                )
            })?;
            Clipboard::new()?.set().wait().text(text).map_err(|e| {
                PasswordGeneratorError::ClipboardError(format!(
                    "Failed to copy to clipboard: {}",
                    e
                ))
            })?;
            loop {
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
        } else {
            process::Command::new(env::current_exe()?)
                .arg(DAEMONIZE_ARG)
                .stdin(process::Stdio::null())
                .stdout(process::Stdio::null())
                .stderr(process::Stdio::null())
                .env("CLIPBOARD_TEXT", text)
                .current_dir("/")
                .spawn()
                .map_err(|e| {
                    PasswordGeneratorError::ClipboardError(format!(
                        "Failed to spawn daemon process: {}",
                        e
                    ))
                })?;
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let mut clipboard = Clipboard::new().map_err(|e| {
            PasswordGeneratorError::ClipboardError(format!("Failed to access clipboard: {}", e))
        })?;

        clipboard.set_text(text.to_owned()).map_err(|e| {
            PasswordGeneratorError::ClipboardError(format!("Failed to copy to clipboard: {}", e))
        })?;
    }

    Ok(())
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

async fn interactive_mode() -> Result<()> {
    let term = Term::stdout();
    let theme = ColorfulTheme::default();

    loop {
        term.clear_screen()?;
        println!("{}", "Welcome to NPWG Interactive Mode!".bold().cyan());

        let options = vec![
            "Generate Password",
            "Generate Passphrase",
            "Mutate Password",
            "Exit",
        ];
        let selection = Select::with_theme(&theme)
            .with_prompt("What would you like to do?")
            .items(&options)
            .default(0)
            .interact_on(&term)
            .map_err(|e| PasswordGeneratorError::DialoguerError(e))?;

        match selection {
            0 => generate_interactive_password(&term, &theme).await?,
            1 => generate_interactive_passphrase(&term, &theme).await?,
            2 => mutate_interactive_password(&term, &theme).await?,
            3 => break,
            _ => unreachable!(),
        }

        if !Confirm::with_theme(&theme)
            .with_prompt("Do you want to perform another action?")
            .default(true)
            .interact_on(&term)
            .map_err(|e| PasswordGeneratorError::DialoguerError(e))?
        {
            break;
        }
    }

    println!("{}", "Thank you for using NPWG!".bold().green());
    Ok(())
}

async fn generate_interactive_password(term: &Term, theme: &ColorfulTheme) -> Result<()> {
    let length: u8 = Input::with_theme(theme)
        .with_prompt("Password length")
        .default(16)
        .interact_on(term)?;

    let count: u32 = Input::with_theme(theme)
        .with_prompt("Number of passwords")
        .default(1)
        .interact_on(term)?;

    let avoid_repeating = Confirm::with_theme(theme)
        .with_prompt("Avoid repeating characters?")
        .default(false)
        .interact_on(term)?;

    let pronounceable = Confirm::with_theme(theme)
        .with_prompt("Generate pronounceable passwords?")
        .default(false)
        .interact_on(term)?;

    let mut config = PasswordGeneratorConfig::new();
    config.length = length as usize;
    config.num_passwords = count as usize;
    config.set_avoid_repeating(avoid_repeating);
    config.pronounceable = pronounceable;
    config.validate()?;

    let pattern = Input::with_theme(theme)
        .with_prompt("Enter desired pattern or leave empty for no pattern")
        .default("".to_string())
        .interact_text()?;

    if !pattern.is_empty() {
        config.pattern = Some(pattern);
    }

    let passwords = if pronounceable {
        generate_pronounceable_passwords(&config).await
    } else {
        generate_passwords(&config).await
    };

    println!("\n{}", "Generated Passwords:".bold().green());
    passwords.iter().for_each(|p| println!("{}", p.yellow()));

    if Confirm::with_theme(theme)
        .with_prompt("Show strength meter?")
        .default(true)
        .interact_on(term)?
    {
        print_strength_meter(&passwords);
    }

    if Confirm::with_theme(theme)
        .with_prompt("Show statistics?")
        .default(false)
        .interact_on(term)?
    {
        print_stats(&passwords);
    }

    passwords.into_iter().for_each(|mut p| p.zeroize());
    Ok(())
}

async fn generate_interactive_passphrase(term: &Term, theme: &ColorfulTheme) -> Result<()> {
    let count: u32 = Input::with_theme(theme)
        .with_prompt("Number of passphrases")
        .default(1)
        .interact_on(term)?;

    let separator: String = Input::with_theme(theme)
        .with_prompt("Separator (single character, 'random', or press Enter for space)")
        .allow_empty(true)
        .interact_on(term)?;

    let wordlist = match diceware::get_wordlist().await {
        Ok(list) => list,
        Err(PasswordGeneratorError::WordlistDownloaded) => {
            println!("Wordlist downloaded. Please run the program again.");
            return Ok(());
        }
        Err(e) => return Err(e),
    };

    let mut config = PasswordGeneratorConfig::new();
    config.num_passwords = count as usize;
    config.set_use_words(true);

    config.separator = if separator.is_empty() {
        Some(Separator::Fixed(' '))
    } else {
        match separator.as_str() {
            "random" => Some(Separator::Random(('a'..='z').chain('0'..='9').collect())),
            s if s.len() == 1 => Some(Separator::Fixed(s.chars().next().unwrap())),
            _ => {
                println!("Invalid separator. Using default (space).");
                Some(Separator::Fixed(' '))
            }
        }
    };

    config.validate()?;

    let passphrases = generate_diceware_passphrase(&wordlist, &config).await;
    println!("\n{}", "Generated Passphrases:".bold().green());
    passphrases.iter().for_each(|p| println!("{}", p.yellow()));

    if Confirm::with_theme(theme)
        .with_prompt("Show strength meter?")
        .default(true)
        .interact_on(term)?
    {
        print_strength_meter(&passphrases);
    }

    if Confirm::with_theme(theme)
        .with_prompt("Show statistics?")
        .default(false)
        .interact_on(term)?
    {
        print_stats(&passphrases);
    }

    Ok(())
}

async fn mutate_interactive_password(term: &Term, theme: &ColorfulTheme) -> Result<()> {
    let password: String = Input::with_theme(theme)
        .with_prompt("Enter the password to mutate")
        .interact_on(term)?;

    let config = PasswordGeneratorConfig::new();
    config.validate()?;

    let lengthen: usize = Input::with_theme(theme)
        .with_prompt("Increase the length of the password")
        .default(0)
        .interact_on(term)?;

    let mutation_strength: u32 = Input::with_theme(theme)
        .with_prompt("Enter mutation strength (1-10)")
        .validate_with(|input: &u32| {
            if *input >= 1 && *input <= 10 {
                Ok(())
            } else {
                Err("Please enter a number between 1 and 10")
            }
        })
        .default(1)
        .interact_on(term)?;

    let mutation_types = vec![
        MutationType::Replace,
        MutationType::Insert,
        MutationType::Remove,
        MutationType::Swap,
        MutationType::Shift,
    ];
    let mutation_type_index = Select::with_theme(theme)
        .with_prompt("Select mutation type")
        .items(&mutation_types)
        .default(0)
        .interact_on(term)?;
    let mutation_type = &mutation_types[mutation_type_index];

    let mutated = mutate_password(&password, &config, lengthen, mutation_strength);

    println!("\n{}", "Mutated Password:".bold().green());
    println!("Original: {}", password.yellow());
    println!("Mutated:  {} (using {:?})", mutated.green(), mutation_type);

    if Confirm::with_theme(theme)
        .with_prompt("Show strength meter?")
        .default(true)
        .interact_on(term)?
    {
        print_strength_meter(&vec![password.clone(), mutated.clone()]);
    }

    if Confirm::with_theme(theme)
        .with_prompt("Show statistics?")
        .default(false)
        .interact_on(term)?
    {
        print_stats(&vec![password, mutated]);
    }

    Ok(())
}
