// SPDX-License-Identifier: MIT
// Project: npwg
// File: src/interactive.rs
// Author: Volker Schwaberow <volker@schwaberow.de>
// Copyright (c) 2022 Volker Schwaberow

use crate::config::{PasswordGeneratorConfig, Separator};
use crate::diceware;
use crate::error::{PasswordGeneratorError, Result};
use crate::generator::{
    generate_diceware_passphrase, generate_passwords, generate_pronounceable_passwords,
    mutate_password, MutationType,
};
use crate::stats::show_stats;
use crate::strength::{evaluate_password_strength, get_strength_bar, get_strength_feedback, get_improvement_suggestions};
use colored::Colorize;
use console::Term;
use dialoguer::{theme::ColorfulTheme, Confirm, Input, Select};
use zeroize::Zeroize;

// Main interactive mode function
pub async fn interactive_mode() -> Result<()> {
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

// Helper function to generate passwords interactively
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

// Helper function to generate passphrases interactively
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

// Helper function to mutate passwords interactively
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

// Helper function to display strength meter
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

// Helper function to display statistics
fn print_stats(data: &[String]) {
    let pq = show_stats(data);
    println!("\n{}", "Statistics:".blue().bold());
    println!("Mean: {:.6}", pq.mean.to_string().yellow());
    println!("Variance: {:.6}", pq.variance.to_string().yellow());
    println!("Skewness: {:.6}", pq.skewness.to_string().yellow());
    println!("Kurtosis: {:.6}", pq.kurtosis.to_string().yellow());
}