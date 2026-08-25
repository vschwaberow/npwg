// SPDX-License-Identifier: MIT
// Project: npwg
// File: src/interactive.rs
// Author: Volker Schwaberow <volker@schwaberow.de>
// Copyright (c) 2022 Volker Schwaberow

use crate::config::PasswordGeneratorConfig;
use crate::diceware;
use crate::error::{PasswordGeneratorError, Result};
use crate::generator::{
    generate_diceware_passphrase, generate_passwords, generate_pronounceable_passwords,
    mutate_password, MutationType,
};
use crate::profile::parse_separator;
use crate::stats::print_stats;
use crate::strength::print_strength_meter;
use colored::Colorize;
use console::Term;
use dialoguer::{theme::ColorfulTheme, Confirm, Input, Select};
use zeroize::Zeroize;

enum MenuAction {
    Password,
    Passphrase,
    Mutate,
    Exit,
}

const MENU_LABELS: [&str; 4] = [
    "Generate Password",
    "Generate Passphrase",
    "Mutate Password",
    "Exit",
];

pub async fn interactive_mode() -> Result<()> {
    let term = Term::stdout();
    let theme = ColorfulTheme::default();

    loop {
        term.clear_screen()?;
        println!("{}", "Welcome to NPWG Interactive Mode!".bold().cyan());

        let selection = Select::with_theme(&theme)
            .with_prompt("What would you like to do?")
            .items(MENU_LABELS)
            .default(0)
            .interact_on(&term)
            .map_err(PasswordGeneratorError::DialoguerError)?;

        let action = match selection {
            0 => MenuAction::Password,
            1 => MenuAction::Passphrase,
            2 => MenuAction::Mutate,
            3 => MenuAction::Exit,
            _ => unreachable!(),
        };

        match action {
            MenuAction::Exit => break,
            other => {
                let action_result = match other {
                    MenuAction::Password => generate_interactive_password(&term, &theme).await,
                    MenuAction::Passphrase => generate_interactive_passphrase(&term, &theme).await,
                    MenuAction::Mutate => mutate_interactive_password(&term, &theme).await,
                    MenuAction::Exit => unreachable!(),
                };

                if let Err(err) = action_result {
                    eprintln!("{}: {}", "Error".red().bold(), err);
                    let _ = Confirm::with_theme(&theme)
                        .with_prompt("Continue?")
                        .default(true)
                        .interact_on(&term);
                    continue;
                }

                if !Confirm::with_theme(&theme)
                    .with_prompt("Do you want to perform another action?")
                    .default(true)
                    .interact_on(&term)
                    .map_err(PasswordGeneratorError::DialoguerError)?
                {
                    break;
                }
            }
        }
    }

    println!("{}", "Thank you for using NPWG!".bold().green());
    Ok(())
}

async fn generate_interactive_password(term: &Term, theme: &ColorfulTheme) -> Result<()> {
    let length: u8 = Input::with_theme(theme)
        .with_prompt("Password length")
        .default(16)
        .validate_with(at_least_one_u8)
        .interact_on(term)?;

    let count: u32 = Input::with_theme(theme)
        .with_prompt("Number of passwords")
        .default(1)
        .validate_with(at_least_one_u32)
        .interact_on(term)?;

    let pronounceable = Confirm::with_theme(theme)
        .with_prompt("Generate pronounceable passwords?")
        .default(false)
        .interact_on(term)?;

    let mut config = PasswordGeneratorConfig::new();
    config.length = length as usize;
    config.num_passwords = count as usize;
    config.pronounceable = pronounceable;

    if !pronounceable {
        let avoid_repeating = Confirm::with_theme(theme)
            .with_prompt("Avoid repeating characters?")
            .default(false)
            .interact_on(term)?;
        config.set_avoid_repeating(avoid_repeating);

        let pattern = Input::with_theme(theme)
            .with_prompt("Pattern (L=letter, D=digit, S=symbol; e.g. LLDDS) or leave empty")
            .default("".to_string())
            .validate_with(|input: &String| validate_pattern_template(input))
            .interact_on(term)?;
        if !pattern.is_empty() {
            config.pattern = Some(pattern);
        }
    }

    config.validate()?;

    let mut passwords = if pronounceable {
        generate_pronounceable_passwords(&config).await?
    } else {
        generate_passwords(&config).await?
    };

    finish_generated_secrets(term, theme, "Generated Passwords:", &mut passwords)?;
    Ok(())
}

async fn generate_interactive_passphrase(term: &Term, theme: &ColorfulTheme) -> Result<()> {
    let count: u32 = Input::with_theme(theme)
        .with_prompt("Number of passphrases")
        .default(1)
        .validate_with(at_least_one_u32)
        .interact_on(term)?;

    let words: u8 = Input::with_theme(theme)
        .with_prompt("Number of words per passphrase")
        .default(6)
        .validate_with(at_least_one_u8)
        .interact_on(term)?;

    let separator: String = Input::with_theme(theme)
        .with_prompt("Separator (single character, 'random', or press Enter for space)")
        .allow_empty(true)
        .interact_on(term)?;

    let wordlist = diceware::get_wordlist().await?;

    let mut config = PasswordGeneratorConfig::new();
    config.num_passwords = count as usize;
    config.length = words as usize;
    config.set_use_words(true);

    config.separator = if separator.is_empty() {
        Some(parse_separator(" ")?)
    } else {
        Some(parse_separator(&separator)?)
    };

    config.validate()?;

    let mut passphrases = generate_diceware_passphrase(&wordlist, &config).await?;
    finish_generated_secrets(term, theme, "Generated Passphrases:", &mut passphrases)?;
    Ok(())
}

async fn mutate_interactive_password(term: &Term, theme: &ColorfulTheme) -> Result<()> {
    let mut password: String = Input::with_theme(theme)
        .with_prompt("Enter the password to mutate")
        .validate_with(|input: &String| {
            if input.is_empty() {
                Err("Password must not be empty")
            } else {
                Ok(())
            }
        })
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
            if (1..=10).contains(input) {
                Ok(())
            } else {
                Err("Please enter a number between 1 and 10")
            }
        })
        .default(1)
        .interact_on(term)?;

    let mutation_types = [
        MutationType::Replace,
        MutationType::Insert,
        MutationType::Remove,
        MutationType::Swap,
        MutationType::Shift,
    ];
    let mutation_labels = ["Random", "Replace", "Insert", "Remove", "Swap", "Shift"];
    let mutation_type_index = Select::with_theme(theme)
        .with_prompt("Select mutation type")
        .items(mutation_labels)
        .default(0)
        .interact_on(term)?;
    let forced_mutation_type = if mutation_type_index == 0 {
        None
    } else {
        Some(&mutation_types[mutation_type_index - 1])
    };
    let mutation_type_display = mutation_labels[mutation_type_index];

    let mut mutated = mutate_password(
        &password,
        &config,
        lengthen,
        mutation_strength,
        forced_mutation_type,
    )?;

    println!("\n{}", "Mutated Password:".bold().green());
    println!("Original: {}", password.yellow());
    println!(
        "Mutated:  {} (using {})",
        mutated.green(),
        mutation_type_display
    );

    if Confirm::with_theme(theme)
        .with_prompt("Show strength meter?")
        .default(true)
        .interact_on(term)?
    {
        print_strength_meter(&[&password, &mutated], true);
    }

    if Confirm::with_theme(theme)
        .with_prompt("Show statistics?")
        .default(false)
        .interact_on(term)?
    {
        print_stats(&[&password, &mutated]);
    }

    password.zeroize();
    mutated.zeroize();
    Ok(())
}

fn finish_generated_secrets(
    term: &Term,
    theme: &ColorfulTheme,
    title: &str,
    secrets: &mut [String],
) -> Result<()> {
    println!("\n{}", title.bold().green());
    secrets.iter().for_each(|p| println!("{}", p.yellow()));

    if Confirm::with_theme(theme)
        .with_prompt("Show strength meter?")
        .default(true)
        .interact_on(term)?
    {
        print_strength_meter(secrets, true);
    }

    if Confirm::with_theme(theme)
        .with_prompt("Show statistics?")
        .default(false)
        .interact_on(term)?
    {
        print_stats(secrets);
    }

    secrets.iter_mut().for_each(|p| p.zeroize());
    Ok(())
}

fn at_least_one_u8(value: &u8) -> std::result::Result<(), &'static str> {
    if *value >= 1 {
        Ok(())
    } else {
        Err("Value must be at least 1")
    }
}

fn at_least_one_u32(value: &u32) -> std::result::Result<(), &'static str> {
    if *value >= 1 {
        Ok(())
    } else {
        Err("Value must be at least 1")
    }
}

fn validate_pattern_template(pattern: &str) -> std::result::Result<(), &'static str> {
    if pattern.is_empty() {
        return Ok(());
    }
    if pattern
        .chars()
        .all(|c| matches!(c, 'L' | 'l' | 'D' | 'd' | 'S' | 's'))
    {
        Ok(())
    } else {
        Err("Use only L, D, or S (e.g. LLDDS). Not a literal password.")
    }
}
