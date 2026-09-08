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
mod pwned;
mod stats;
mod strength;

const DAEMONIZE_ARG: &str = "__internal_daemonize";
const CLIPBOARD_DAEMON_HOLD_SECS: u64 = 45;

use std::io::Write;

use arboard::Clipboard;
#[cfg(target_os = "linux")]
use arboard::SetExtLinux;
use clap::{parser::ValueSource, value_parser, Arg, ArgAction, ArgGroup, Command};
use clap_complete::{
    generate,
    shells::{Bash, Fish, Zsh},
    Shell,
};
use colored::*;
use config::{PasswordGeneratorConfig, PasswordGeneratorMode, Separator};
use dialoguer::{Input, Password};
use error::{PasswordGeneratorError, Result};
use generator::{
    effective_allowed_chars, generate_deterministic_password, generate_diceware_passphrase,
    generate_diceware_passphrase_with_min_entropy, generate_passwords_with_min_entropy,
    generate_passwords_with_min_entropy_and_wordlist, generate_passwords_with_wordlist,
    generate_pronounceable_passwords, mutate_password, MutationType,
};
use policy::{apply_policy, PolicyName};
use profile::{apply_allowed_sets, apply_profile, load_user_profiles, parse_separator};
use qrcodegen::{QrCode, QrCodeEcc};
use stats::{print_stats, print_stats_to};
use strength::{print_strength_meter, print_strength_meter_to};
use zeroize::{Zeroize, Zeroizing};

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

    if let Some(shell) = matches.get_one::<Shell>("completions").copied() {
        let mut cmd = build_cli();
        let name = cmd.get_name().to_string();
        match shell {
            Shell::Bash => generate(Bash, &mut cmd, name, &mut std::io::stdout()),
            Shell::Zsh => generate(Zsh, &mut cmd, name, &mut std::io::stdout()),
            Shell::Fish => generate(Fish, &mut cmd, name, &mut std::io::stdout()),
            _ => {
                return Err(PasswordGeneratorError::InvalidConfig(
                    "Supported shells for --completions: bash, zsh, fish.".to_string(),
                ));
            }
        }
        return Ok(());
    }

    if matches.get_flag("interactive") {
        return interactive::interactive_mode().await;
    }

    let config = build_config(&matches)?;
    if config.seed.is_some() {
        eprintln!(
            "{}",
            "Warning: --seed makes output predictable; do not use for real secrets.".yellow()
        );
    }

    let copy = matches.get_flag("copy");

    if matches.get_flag("deterministic") {
        return handle_deterministic(&config, &matches, copy).await;
    }

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
            Arg::new("no-ambiguous")
                .long("no-ambiguous")
                .help("Exclude ambiguous characters (0 O o 1 l I |)")
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
        .arg(
            Arg::new("check-pwned")
                .long("check-pwned")
                .help("Reject secrets found in Have I Been Pwned (k-anonymity range API)")
                .action(ArgAction::SetTrue),
        )
        .group(
            ArgGroup::new("output_options")
                .args(["stats", "strength", "check-pwned"])
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
            Arg::new("require")
                .long("require")
                .value_name("CLASSES")
                .help("Append required character classes to diceware passphrases (digit,symbol)")
                .requires("use-words"),
        )
        .arg(
            Arg::new("wordlist-preset")
                .long("wordlist-preset")
                .value_name("PRESET")
                .help("Built-in diceware wordlist preset (eff-large, eff-short) [default: eff-large]"),
        )
        .arg(
            Arg::new("wordlist")
                .long("wordlist")
                .value_name("PATH")
                .help("Path to a custom diceware wordlist (tab or plain words)"),
        )
        .arg(
            Arg::new("pronounceable")
                .long("pronounceable")
                .help("Generate pronounceable passwords")
                .action(ArgAction::SetTrue)
                .conflicts_with_all(["pattern", "use-words"]),
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
                .help("Type of mutation to apply (omit for random)")
                .value_parser(value_parser!(MutationType))
                .requires("mutate"),
        )
        .arg(
            Arg::new("mutation_strength")
                .long("mutation-strength")
                .help("Strength of mutation")
                .default_value("1")
                .value_parser(value_parser!(u32))
                .requires("mutate"),
        )
        .arg(
            Arg::new("lengthen")
                .long("lengthen")
                .value_name("INCREASE")
                .help("Increase the length of passwords during mutation")
                .value_parser(value_parser!(usize))
                .requires("mutate"),
        )
        .arg(
            Arg::new("copy")
                .long("copy")
                .help("Copy the generated password to the clipboard")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("qr")
                .long("qr")
                .help("Print as QR code")
                .action(ArgAction::SetTrue)
                .conflicts_with_all(["json", "null"]),
        )
        .arg(
            Arg::new("json")
                .long("json")
                .help("Print secrets as a JSON array on stdout")
                .action(ArgAction::SetTrue)
                .conflicts_with_all(["null", "qr"]),
        )
        .arg(
            Arg::new("null")
                .long("null")
                .help("Print secrets NUL-separated on stdout")
                .action(ArgAction::SetTrue)
                .conflicts_with_all(["json", "qr"]),
        )
        .arg(
            Arg::new("pattern")
                .short('p')
                .long("pattern")
                .help("Pattern for password generation (e.g., LLDDS or {L:4}{D:2}-{word})")
                .value_parser(value_parser!(String))
                .conflicts_with_all(["pronounceable", "use-words"]),
        )
        .group(
            ArgGroup::new("generation")
                .args([
                    "pattern",
                    "avoid-repeating",
                    "no-ambiguous",
                    "allowed",
                    "use-words",
                    "separator",
                    "require",
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
            Arg::new("min-entropy")
                .long("min-entropy")
                .value_name("BITS")
                .help("Regenerate until estimated entropy reaches at least BITS (character-class heuristic)")
                .value_parser(value_parser!(f64))
                .conflicts_with_all(["seed", "deterministic", "mutate"]),
        )
        .arg(
            Arg::new("seed")
                .short('s')
                .long("seed")
                .value_name("SEED")
                .help("Seed the RNG for reproducible output (insecure for real secrets; testing only)")
                .value_parser(value_parser!(u64)),
        )
        .arg(
            Arg::new("deterministic")
                .long("deterministic")
                .help("Generate passwords deterministically from a master password and service")
                .action(ArgAction::SetTrue)
                .conflicts_with_all([
                    "use-words",
                    "separator",
                    "pronounceable",
                    "mutate",
                    "seed",
                    "pattern",
                    "min-entropy",
                ]),
        )
        .arg(
            Arg::new("service")
                .short('S')
                .long("service")
                .value_name("SERVICE")
                .help("Service or context name used as salt for deterministic generation")
                .requires("deterministic"),
        )
        .arg(
            Arg::new("username")
                .short('u')
                .long("username")
                .value_name("USERNAME")
                .help("Optional username for deterministic generation")
                .requires("deterministic"),
        )
        .arg(
            Arg::new("counter")
                .long("counter")
                .value_name("COUNTER")
                .help("Counter for deterministic generation")
                .default_value("1")
                .value_parser(value_parser!(u32))
                .requires("deterministic"),
        )
        .arg(
            Arg::new("completions")
                .long("completions")
                .value_name("SHELL")
                .help("Print shell completion script to stdout and exit (bash, zsh, fish)")
                .value_parser(value_parser!(Shell)),
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

    if matches.value_source("length") == Some(ValueSource::CommandLine) {
        config.length = *matches.get_one::<u8>("length").unwrap() as usize;
    }
    if matches.value_source("count") == Some(ValueSource::CommandLine) {
        config.num_passwords = *matches.get_one::<u32>("count").unwrap() as usize;
    }
    if matches.get_flag("avoid-repeating") {
        config.set_avoid_repeating(true);
    }
    if matches.get_flag("no-ambiguous") {
        config.exclude_ambiguous();
    }
    if matches.value_source("seed") == Some(ValueSource::CommandLine) {
        config.seed = matches.get_one::<u64>("seed").copied();
    }

    if matches.value_source("allowed") == Some(ValueSource::CommandLine) {
        let allowed = matches.get_one::<String>("allowed").unwrap();
        apply_allowed_sets(&mut config, allowed)?;
    }

    if matches.get_flag("use-words") {
        config.set_use_words(true);
    }

    if matches.value_source("require") == Some(ValueSource::CommandLine) {
        let raw = matches.get_one::<String>("require").unwrap();
        config.require_classes = PasswordGeneratorConfig::parse_require_list(raw)?;
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

    if let Some(policy) = matches.get_one::<PolicyName>("policy").copied() {
        let details = apply_policy(policy, &mut config)?;
        let policy_msg = format!(
            "Applying policy {} ({}). Minimum length: {} characters, recommended entropy ≈ {:.1} bits.",
            details.label.green(),
            details.description,
            details.minimum_length,
            details.recommended_entropy_bits
        );
        if machine_output_mode(matches) {
            eprintln!("{}", policy_msg);
        } else {
            println!("{}", policy_msg);
        }
        if config.length < details.minimum_length {
            let clamp_msg = format!(
                "Policy requires at least {} characters; clamping requested length to {}.",
                details.minimum_length, details.minimum_length
            )
            .yellow()
            .to_string();
            if machine_output_mode(matches) {
                eprintln!("{}", clamp_msg);
            } else {
                println!("{}", clamp_msg);
            }
            config.length = details.minimum_length;
        }
    }

    if config.mode == PasswordGeneratorMode::Diceware && config.separator.is_none() {
        config.separator = Some(Separator::Fixed(' '));
    }

    config.validate()?;
    Ok(config)
}

fn min_entropy_bits(matches: &clap::ArgMatches) -> Option<f64> {
    matches.get_one::<f64>("min-entropy").copied()
}

fn resolve_wordlist_source(matches: &clap::ArgMatches) -> Result<diceware::WordlistSource> {
    if matches.value_source("wordlist") == Some(ValueSource::CommandLine) {
        let path = matches.get_one::<String>("wordlist").unwrap();
        return Ok(diceware::WordlistSource::Path(path.into()));
    }
    let preset_raw = matches
        .get_one::<String>("wordlist-preset")
        .map(|s| s.as_str())
        .unwrap_or("eff-large");
    let preset = diceware::WordlistPreset::parse(preset_raw)?;
    Ok(diceware::WordlistSource::Preset(preset))
}

async fn handle_diceware(
    config: &PasswordGeneratorConfig,
    matches: &clap::ArgMatches,
    copy: bool,
) -> Result<()> {
    let wordlist = diceware::get_wordlist(&resolve_wordlist_source(matches)?).await?;
    let passphrases = match min_entropy_bits(matches) {
        Some(min_bits) => {
            generate_diceware_passphrase_with_min_entropy(&wordlist, config, min_bits).await?
        }
        None => generate_diceware_passphrase(&wordlist, config).await?,
    };
    finish_cli_secrets(
        passphrases,
        matches,
        copy,
        "Passphrase(s) copied to clipboard.",
    )
    .await
}

async fn handle_password(
    config: &PasswordGeneratorConfig,
    matches: &clap::ArgMatches,
    copy: bool,
) -> Result<()> {
    let pattern_words = load_pattern_wordlist(config, matches).await?;
    let passwords = match min_entropy_bits(matches) {
        Some(min_bits) => {
            generate_passwords_with_min_entropy_and_wordlist(
                config,
                min_bits,
                pattern_words.as_deref(),
            )
            .await?
        }
        None => generate_passwords_with_wordlist(config, pattern_words.as_deref()).await?,
    };
    finish_cli_secrets(passwords, matches, copy, "Password(s) copied to clipboard.").await
}

async fn load_pattern_wordlist(
    config: &PasswordGeneratorConfig,
    matches: &clap::ArgMatches,
) -> Result<Option<Vec<String>>> {
    let Some(pattern) = config.pattern.as_deref() else {
        return Ok(None);
    };
    if !generator::pattern_needs_wordlist(pattern) {
        return Ok(None);
    }
    let source = resolve_wordlist_source(matches)?;
    Ok(Some(diceware::get_wordlist(&source).await?))
}

async fn handle_pronounceable(
    config: &PasswordGeneratorConfig,
    matches: &clap::ArgMatches,
    copy: bool,
) -> Result<()> {
    let passwords = match min_entropy_bits(matches) {
        Some(min_bits) => generate_passwords_with_min_entropy(config, min_bits).await?,
        None => generate_pronounceable_passwords(config).await?,
    };
    finish_cli_secrets(
        passwords,
        matches,
        copy,
        "Passphrase(s) copied to clipboard.",
    )
    .await
}

async fn handle_deterministic(
    config: &PasswordGeneratorConfig,
    matches: &clap::ArgMatches,
    copy: bool,
) -> Result<()> {
    if matches!(config.mode, PasswordGeneratorMode::Diceware) {
        return Err(PasswordGeneratorError::InvalidConfig(
            "Deterministic mode does not support diceware.".to_string(),
        ));
    }
    if config.pronounceable {
        return Err(PasswordGeneratorError::InvalidConfig(
            "Deterministic mode does not support pronounceable passwords.".to_string(),
        ));
    }
    if config.pattern.is_some() {
        return Err(PasswordGeneratorError::InvalidConfig(
            "Deterministic mode does not support patterns.".to_string(),
        ));
    }

    let service = matches
        .get_one::<String>("service")
        .ok_or_else(|| {
            PasswordGeneratorError::InvalidConfig(
                "Missing required --service for deterministic mode.".to_string(),
            )
        })?
        .as_str();
    let username = matches.get_one::<String>("username").map(|s| s.as_str());
    let counter = *matches.get_one::<u32>("counter").unwrap_or(&1);

    let master_password = Zeroizing::new(
        Password::new()
            .with_prompt("Master password")
            .allow_empty_password(false)
            .interact()?,
    );

    let allowed_chars = effective_allowed_chars(config)?;
    let mut passwords = Vec::with_capacity(config.num_passwords);
    for index in 0..config.num_passwords {
        let current_counter = counter.checked_add(index as u32).ok_or_else(|| {
            PasswordGeneratorError::InvalidConfig("Counter overflow.".to_string())
        })?;
        let password = generate_deterministic_password(
            master_password.as_str(),
            service,
            username,
            current_counter,
            config.length,
            &allowed_chars,
        )?;
        passwords.push(password);
    }

    finish_cli_secrets(passwords, matches, copy, "Password(s) copied to clipboard.").await
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
        .filter(|s| !s.is_empty())
        .collect();
    if passwords.is_empty() {
        return Err(PasswordGeneratorError::InvalidConfig(
            "No passwords provided to mutate.".to_string(),
        ));
    }

    let lengthen = matches.get_one::<usize>("lengthen").unwrap_or(&0);

    let cli_mutation_type_arg =
        if matches.value_source("mutation_type") == Some(ValueSource::CommandLine) {
            matches.get_one::<MutationType>("mutation_type")
        } else {
            None
        };

    let mutation_strength = matches.get_one::<u32>("mutation_strength").unwrap_or(&1);

    let mut mutated_passwords = Vec::with_capacity(passwords.len());

    println!("\n{}", "Mutated Passwords:".bold().green());
    for mut password in passwords {
        let mutated = mutate_password(
            &password,
            config,
            *lengthen,
            *mutation_strength,
            cli_mutation_type_arg,
        )?;
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
        password.zeroize();
        mutated_passwords.push(mutated);
    }

    if copy && !mutated_passwords.is_empty() {
        copy_secrets_to_clipboard(&mutated_passwords)?;
        println!("{}", "Password(s) copied to clipboard.".bold().green());
    }

    if matches.get_flag("strength") {
        print_strength_meter(&mutated_passwords, true);
    }

    if matches.get_flag("stats") {
        print_stats(&mutated_passwords);
    }

    mutated_passwords.into_iter().for_each(|mut p| p.zeroize());
    Ok(())
}

fn machine_output_mode(matches: &clap::ArgMatches) -> bool {
    matches.get_flag("json") || matches.get_flag("null")
}

fn format_secrets_json(secrets: &[String]) -> Result<String> {
    serde_json::to_string(secrets).map_err(|e| {
        PasswordGeneratorError::InvalidConfig(format!("Failed to encode JSON output: {}", e))
    })
}

fn format_secrets_null(secrets: &[String]) -> Vec<u8> {
    let mut out = Vec::new();
    for secret in secrets {
        out.extend_from_slice(secret.as_bytes());
        out.push(0);
    }
    out
}

async fn finish_cli_secrets(
    mut secrets: Vec<String>,
    matches: &clap::ArgMatches,
    copy: bool,
    copy_label: &str,
) -> Result<()> {
    if matches.get_flag("check-pwned") {
        pwned::ensure_secrets_not_pwned(&secrets).await?;
    }

    let machine = machine_output_mode(matches);
    render_secrets(
        &secrets,
        matches.get_flag("qr"),
        matches.get_flag("json"),
        matches.get_flag("null"),
    )?;

    if copy && !secrets.is_empty() {
        copy_secrets_to_clipboard(&secrets)?;
        let msg = format!("{}", copy_label.bold().green());
        if machine {
            eprintln!("{}", msg);
        } else {
            println!("{}", msg);
        }
    }

    if matches.get_flag("strength") {
        print_strength_meter_to(&secrets, !matches.get_flag("qr") && !machine, machine);
    }

    if matches.get_flag("stats") {
        print_stats_to(&secrets, machine);
    }

    secrets.iter_mut().for_each(|p| p.zeroize());
    Ok(())
}

fn render_secrets(secrets: &[String], as_qr: bool, as_json: bool, as_null: bool) -> Result<()> {
    if as_json {
        let payload = format_secrets_json(secrets)?;
        println!("{}", payload);
    } else if as_null {
        let payload = format_secrets_null(secrets);
        let mut stdout = std::io::stdout().lock();
        stdout.write_all(&payload)?;
    } else if as_qr {
        for secret in secrets {
            print_qr(secret)?;
        }
    } else {
        secrets.iter().for_each(|p| println!("{}", p.green()));
    }
    Ok(())
}

fn print_qr(text: &str) -> Result<()> {
    let qr = QrCode::encode_text(text, QrCodeEcc::Medium)
        .map_err(|e| PasswordGeneratorError::QrCode(format!("Failed to encode QR: {}", e)))?;
    let size = qr.size();
    let quiet_zone: i32 = 4;
    let black = "\x1b[48;2;0;0;0m  \x1b[0m";
    let white = "\x1b[48;2;255;255;255m  \x1b[0m";

    let mut output = String::new();
    for y in -quiet_zone..(size + quiet_zone) {
        for x in -quiet_zone..(size + quiet_zone) {
            let dark = if (0..size).contains(&x) && (0..size).contains(&y) {
                qr.get_module(x, y)
            } else {
                false
            };
            output.push_str(if dark { black } else { white });
        }
        output.push('\n');
    }

    let mut stdout = std::io::stdout().lock();
    stdout.write_all(output.as_bytes())?;
    Ok(())
}

fn copy_secrets_to_clipboard(secrets: &[String]) -> Result<()> {
    let mut clipboard_text = secrets.join("\n");
    let result = copy_to_clipboard(&clipboard_text);
    clipboard_text.zeroize();
    result
}

fn copy_to_clipboard(text: &str) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        use std::env;
        use std::io::Read;

        if env::args().any(|arg| arg == DAEMONIZE_ARG) {
            let mut text = String::new();
            std::io::stdin().read_to_string(&mut text).map_err(|e| {
                PasswordGeneratorError::ClipboardError(format!(
                    "Failed to read clipboard secret from stdin: {}",
                    e
                ))
            })?;
            ensure_clipboard_text(&text)?;
            write_to_clipboard(&text)?;
            text.zeroize();
            std::thread::sleep(std::time::Duration::from_secs(CLIPBOARD_DAEMON_HOLD_SECS));
            clear_clipboard()?;
            return Ok(());
        } else {
            ensure_clipboard_text(text)?;
            spawn_clipboard_daemon(text)?;
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        ensure_clipboard_text(text)?;
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
    use std::io::Write;
    use std::{env, process};

    let mut child = process::Command::new(env::current_exe()?)
        .arg(DAEMONIZE_ARG)
        .stdin(process::Stdio::piped())
        .stdout(process::Stdio::null())
        .stderr(process::Stdio::null())
        .current_dir("/")
        .spawn()
        .map_err(|e| {
            PasswordGeneratorError::ClipboardUnavailable(format!(
                "Failed to spawn clipboard helper: {}",
                e
            ))
        })?;

    let mut stdin = child.stdin.take().ok_or_else(|| {
        PasswordGeneratorError::ClipboardUnavailable(
            "Failed to open clipboard helper stdin".to_string(),
        )
    })?;
    stdin.write_all(text.as_bytes()).map_err(|e| {
        PasswordGeneratorError::ClipboardUnavailable(format!(
            "Failed to write clipboard secret to helper: {}",
            e
        ))
    })?;
    drop(stdin);
    Ok(())
}

#[cfg(target_os = "linux")]
fn clear_clipboard() -> Result<()> {
    let mut clipboard = Clipboard::new().map_err(|e| {
        PasswordGeneratorError::ClipboardUnavailable(format!(
            "Unable to access clipboard backend for clear: {}",
            e
        ))
    })?;
    clipboard.clear().map_err(|e| {
        PasswordGeneratorError::ClipboardError(format!("Failed to clear clipboard: {}", e))
    })?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn clear_clipboard() -> Result<()> {
    Ok(())
}

#[cfg(target_os = "linux")]
fn write_to_clipboard(text: &str) -> Result<()> {
    let mut clipboard = Clipboard::new().map_err(|e| {
        PasswordGeneratorError::ClipboardUnavailable(format!(
            "Unable to access clipboard backend (install wl-clipboard?): {}",
            e
        ))
    })?;

    let mut owned = text.to_string();
    let write_result = clipboard.set().wait().text(owned.clone()).map_err(|e| {
        PasswordGeneratorError::ClipboardError(format!("Failed to write text to clipboard: {}", e))
    });
    owned.zeroize();
    write_result?;

    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn write_to_clipboard(text: &str) -> Result<()> {
    let mut clipboard = Clipboard::new().map_err(|e| {
        PasswordGeneratorError::ClipboardUnavailable(format!("Unable to access clipboard: {}", e))
    })?;

    let mut owned = text.to_owned();
    let write_result = clipboard.set_text(owned.clone()).map_err(|e| {
        PasswordGeneratorError::ClipboardError(format!("Failed to write text to clipboard: {}", e))
    });
    owned.zeroize();
    write_result?;

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
        assert!(!matches.get_flag("use-words"));
        assert!(!matches.get_flag("pronounceable"));
        assert!(matches.value_source("allowed") == Some(ValueSource::DefaultValue));
        assert_eq!(config.allowed_chars.len(), 26);
        assert!(matches!(config.mode, PasswordGeneratorMode::Diceware));
        match config.separator.as_ref().unwrap() {
            Separator::Fixed(separator) => assert_eq!(*separator, '-'),
            _ => panic!(),
        }
    }

    #[test]
    fn test_cli_rejects_use_words_with_pattern() {
        let result =
            build_cli().try_get_matches_from(["npwg", "--use-words", "--pattern", "LLDDS"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_cli_policy_overrides_use_words() {
        let matches = build_cli()
            .try_get_matches_from(["npwg", "--use-words", "--policy", "windows-ad"])
            .unwrap();
        let config = build_config(&matches).unwrap();
        assert!(matches!(config.mode, PasswordGeneratorMode::Password));
    }

    #[test]
    fn test_cli_mutation_type_defaults_to_random() {
        let matches = build_cli()
            .try_get_matches_from(["npwg", "--mutate"])
            .unwrap();
        assert_ne!(
            matches.value_source("mutation_type"),
            Some(ValueSource::CommandLine)
        );
    }

    #[test]
    fn test_cli_mutation_type_from_command_line() {
        let matches = build_cli()
            .try_get_matches_from(["npwg", "--mutate", "--mutation-type", "swap"])
            .unwrap();
        assert_eq!(
            matches.value_source("mutation_type"),
            Some(ValueSource::CommandLine)
        );
        assert_eq!(
            matches
                .get_one::<MutationType>("mutation_type")
                .map(|t| t.to_string())
                .as_deref(),
            Some("swap")
        );
    }

    #[test]
    fn test_cli_lengthen_requires_mutate() {
        let result = build_cli().try_get_matches_from(["npwg", "--lengthen", "3"]);
        assert!(result.is_err());
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
    #[test]
    fn test_cli_parses_completions_shell() {
        let matches = build_cli()
            .try_get_matches_from(["npwg", "--completions", "bash"])
            .unwrap();
        assert_eq!(
            matches.get_one::<Shell>("completions").copied(),
            Some(Shell::Bash)
        );
    }

    #[test]
    fn test_cli_json_conflicts_with_null() {
        let result = build_cli().try_get_matches_from(["npwg", "--json", "--null"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_cli_json_conflicts_with_qr() {
        let result = build_cli().try_get_matches_from(["npwg", "--json", "--qr"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_format_secrets_json_array() {
        let payload = format_secrets_json(&["a".into(), "b\"c".into()]).unwrap();
        assert_eq!(payload, r#"["a","b\"c"]"#);
    }

    #[test]
    fn test_format_secrets_null_separated() {
        let payload = format_secrets_null(&["one".into(), "two".into()]);
        assert_eq!(payload, b"one\0two\0");
    }

    #[test]
    fn test_cli_parses_check_pwned() {
        let matches = build_cli()
            .try_get_matches_from(["npwg", "--check-pwned"])
            .unwrap();
        assert!(matches.get_flag("check-pwned"));
    }

    #[test]
    fn test_cli_parses_wordlist_without_use_words() {
        let matches = build_cli()
            .try_get_matches_from(["npwg", "--wordlist", "/tmp/x"])
            .unwrap();
        assert_eq!(
            matches.get_one::<String>("wordlist").map(String::as_str),
            Some("/tmp/x")
        );
    }

    #[test]
    fn test_cli_resolves_wordlist_path() {
        let matches = build_cli()
            .try_get_matches_from(["npwg", "--use-words", "--wordlist", "/tmp/words.txt"])
            .unwrap();
        match resolve_wordlist_source(&matches).unwrap() {
            diceware::WordlistSource::Path(path) => {
                assert_eq!(path, std::path::PathBuf::from("/tmp/words.txt"));
            }
            other => panic!("expected path source, got {other:?}"),
        }
    }

    #[test]
    fn test_cli_resolves_wordlist_preset_short() {
        let matches = build_cli()
            .try_get_matches_from(["npwg", "--use-words", "--wordlist-preset", "eff-short"])
            .unwrap();
        match resolve_wordlist_source(&matches).unwrap() {
            diceware::WordlistSource::Preset(diceware::WordlistPreset::EffShort) => {}
            other => panic!("expected eff-short, got {other:?}"),
        }
    }

    #[test]
    fn test_cli_require_needs_use_words() {
        let result = build_cli().try_get_matches_from(["npwg", "--require", "digit"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_cli_parses_require_classes() {
        let matches = build_cli()
            .try_get_matches_from(["npwg", "--use-words", "--require", "digit,symbol"])
            .unwrap();
        let config = build_config(&matches).unwrap();
        assert_eq!(
            config.require_classes,
            vec![config::RequireClass::Digit, config::RequireClass::Symbol]
        );
    }

    #[test]
    fn test_cli_no_ambiguous_excludes_lookalikes() {
        let matches = build_cli()
            .try_get_matches_from(["npwg", "--no-ambiguous"])
            .unwrap();
        let config = build_config(&matches).unwrap();
        let chars = effective_allowed_chars(&config).unwrap();
        for c in config::AMBIGUOUS_CHARS {
            assert!(!chars.contains(c));
        }
    }

    #[test]
    fn test_cli_parses_min_entropy() {
        let matches = build_cli()
            .try_get_matches_from(["npwg", "--min-entropy", "80", "--length", "20"])
            .unwrap();
        assert_eq!(matches.get_one::<f64>("min-entropy").copied(), Some(80.0));
    }

    #[test]
    fn test_cli_min_entropy_conflicts_with_seed() {
        let result =
            build_cli().try_get_matches_from(["npwg", "--min-entropy", "80", "--seed", "1"]);
        assert!(result.is_err());
    }
}
