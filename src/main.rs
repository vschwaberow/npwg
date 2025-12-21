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
mod policy;
mod profile;
mod stats;
mod strength;

const DAEMONIZE_ARG: &str = "__internal_daemonize";

use std::process;

use arboard::Clipboard;
#[cfg(target_os = "linux")]
use arboard::SetExtLinux;
use clap::{parser::ValueSource, value_parser, Arg, ArgAction, ArgGroup, Command};
use colored::*;
use config::{PasswordGeneratorConfig, PasswordGeneratorMode, Separator};
use dialoguer::Input;
use error::{PasswordGeneratorError, Result};
use generator::{
    generate_diceware_passphrase, generate_passwords, generate_pronounceable_passwords,
    mutate_password, MutationType,
};
use policy::{apply_policy, PolicyName};
use profile::{apply_allowed_sets, apply_profile, load_user_profiles, parse_separator};
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
            Arg::new("config")
                .long("config")
                .value_name("PATH")
                .help("Path to a configuration file with defaults and profiles"),
        )
        .arg(
            Arg::new("profile")
                .long("profile")
                .value_name("NAME")
                .help("Name of a profile from the configuration file"),
        )
        .arg(
            Arg::new("policy")
                .long("policy")
                .value_name("POLICY")
                .help("Apply a built-in password policy (windows-ad, pci-dss, nist-high)")
                .value_parser(value_parser!(PolicyName)),
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
                .default_value("1")
                .value_parser(value_parser!(u32)),
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
    let profiles = load_user_profiles(matches.get_one::<String>("config"))?;
    if let Some(defaults) = profiles.defaults() {
        apply_profile(defaults, &mut config)?;
    }
    if let Some(profile_name) = matches.get_one::<String>("profile") {
        let profile_definition = profiles.get(profile_name).ok_or_else(|| {
            PasswordGeneratorError::ConfigFile(format!("Unknown profile '{}'", profile_name))
        })?;
        apply_profile(profile_definition, &mut config)?;
    }

    let mut policy_minimum_length: Option<usize> = None;
    if let Some(policy) = matches.get_one::<PolicyName>("policy").copied() {
        let details = apply_policy(policy, &mut config)?;
        println!(
            "Applying policy {} ({}). Minimum length: {} characters, recommended entropy ≈ {:.1} bits.",
            details.label.green(),
            details.description,
            details.minimum_length,
            details.recommended_entropy_bits
        );
        policy_minimum_length = Some(details.minimum_length);
    }

    if matches.value_source("length") == Some(ValueSource::CommandLine) {
        config.length = *matches.get_one::<u8>("length").unwrap() as usize;
    }
    if matches.value_source("count") == Some(ValueSource::CommandLine) {
        config.num_passwords = *matches.get_one::<u32>("count").unwrap() as usize;
    }
    if matches.get_flag("avoid-repeating") {
        config.set_avoid_repeating(true);
    }
    if matches.value_source("seed") == Some(ValueSource::CommandLine) {
        config.seed = matches.get_one::<u64>("seed").copied();
    }

    if matches.value_source("allowed") == Some(ValueSource::CommandLine) {
        let allowed = matches.get_one::<String>("allowed").unwrap();
        if let Err(error) = apply_allowed_sets(&mut config, allowed) {
            match error {
                PasswordGeneratorError::ConfigFile(message) => {
                    eprintln!("Error: {}", message.red());
                    process::exit(1);
                }
                _ => return Err(error),
            }
        }
    }

    if matches.get_flag("use-words") {
        config.set_use_words(true);
    }

    if matches.get_flag("pronounceable") {
        config.pronounceable = true;
    }

    if matches.value_source("separator") == Some(ValueSource::CommandLine) {
        if let Some(separator) = matches.get_one::<String>("separator") {
            config.separator = Some(parse_separator(separator)?);
        }
    }

    if matches.value_source("pattern") == Some(ValueSource::CommandLine) {
        config.pattern = matches.get_one::<String>("pattern").cloned();
    }

    if let Some(min_length) = policy_minimum_length {
        if config.length < min_length {
            println!(
                "{}",
                format!(
                    "Policy requires at least {} characters; clamping requested length to {}.",
                    min_length, min_length
                )
                .yellow()
            );
            config.length = min_length;
        }
    }

    if config.mode == PasswordGeneratorMode::Diceware && config.separator.is_none() {
        config.separator = Some(Separator::Fixed(' '));
    }

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
    use std::io::Write;

    use tempfile::NamedTempFile;

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

    #[test]
    fn test_cli_profile_merges_config_file() {
        let mut file = NamedTempFile::new().unwrap();
        write!(
            file,
            "[defaults]\nlength = 20\nallowed = \"lowerletter\"\n\n[profiles.work]\ncount = 4\nuse_words = true\nseparator = \"-\"\n"
        )
        .unwrap();
        let config_path = file.path().to_str().unwrap();
        let matches = build_cli()
            .try_get_matches_from(["npwg", "--config", config_path, "--profile", "work"])
            .unwrap();
        let config = build_config(&matches).unwrap();
        assert_eq!(config.length, 20);
        assert_eq!(config.num_passwords, 4);
        assert!(matches.get_flag("use-words") == false);
        assert!(matches.get_flag("pronounceable") == false);
        assert!(matches.value_source("allowed") == Some(ValueSource::DefaultValue));
        assert_eq!(config.allowed_chars.len(), 26);
        assert!(matches!(config.mode, PasswordGeneratorMode::Diceware));
        match config.separator.as_ref().unwrap() {
            Separator::Fixed(separator) => assert_eq!(*separator, '-'),
            _ => panic!(),
        }
    }

    #[test]
    fn test_cli_policy_enforces_minimums() {
        let matches = build_cli()
            .try_get_matches_from(["npwg", "--policy", "windows-ad"])
            .unwrap();
        let config = build_config(&matches).unwrap();
        assert!(config.length >= 14);
        assert!(config.allowed_chars.iter().any(|c| c.is_ascii_uppercase()));
        assert!(config.allowed_chars.iter().any(|c| c.is_ascii_lowercase()));
        assert!(config.allowed_chars.iter().any(|c| c.is_ascii_digit()));
        assert!(config
            .allowed_chars
            .iter()
            .any(|c| !c.is_ascii_alphanumeric()));
    }
}
