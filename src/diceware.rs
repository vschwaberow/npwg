// SPDX-License-Identifier: MIT
// Project: npwg
// File: src/diceware.rs
// Author: Volker Schwaberow <volker@schwaberow.de>
// Copyright (c) 2022 Volker Schwaberow

use crate::error::PasswordGeneratorError;
use crate::error::Result;
use dirs::home_dir;
use reqwest::Client;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

const DICEWARE_FILENAME: &str = "diceware_wordlist.txt";
const DICEWARE_URL: &str = "https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt";
const DICEWARE_CHECKSUM_FILENAME: &str = "diceware_wordlist.sha256";
const DICEWARE_TIMEOUT: Duration = Duration::from_secs(15);
const EXPECTED_WORDLIST_LINES: usize = 7776;

pub async fn get_wordlist() -> Result<Vec<String>> {
    let home = home_dir().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::NotFound, "Home directory not found")
    })?;
    let workdir = home.join(".npwg");
    let wordlist_path = workdir.join(DICEWARE_FILENAME);

    if wordlist_path.exists() {
        return load_wordlist(&wordlist_path);
    }

    download_wordlist(&workdir, &wordlist_path).await?;
    Err(PasswordGeneratorError::WordlistDownloaded)
}

fn load_wordlist(wordlist_path: &Path) -> Result<Vec<String>> {
    let contents = fs::read_to_string(wordlist_path)?;
    validate_wordlist(&contents, wordlist_path)?;
    Ok(parse_wordlist(&contents))
}

async fn download_wordlist(workdir: &Path, wordlist_path: &Path) -> Result<()> {
    println!("Downloading wordlist from {}", DICEWARE_URL);

    fs::create_dir_all(workdir)?;

    let client = Client::builder().timeout(DICEWARE_TIMEOUT).build()?;
    let response = client.get(DICEWARE_URL).send().await?.error_for_status()?;
    let bytes = response.bytes().await?;

    if bytes.is_empty() {
        return Err(PasswordGeneratorError::WordlistValidation(
            "Downloaded wordlist was empty".to_string(),
        ));
    }

    let contents = String::from_utf8(bytes.to_vec()).map_err(|err| {
        PasswordGeneratorError::WordlistValidation(format!(
            "Downloaded wordlist was not valid UTF-8: {}",
            err
        ))
    })?;

    fs::write(wordlist_path, contents.as_bytes())?;
    validate_wordlist(&contents, wordlist_path)?;

    println!("Wordlist downloaded to {:?}", wordlist_path);
    Ok(())
}

fn parse_wordlist(contents: &str) -> Vec<String> {
    contents
        .lines()
        .filter_map(|line| line.split_once('\t'))
        .map(|(_, word)| word.to_string())
        .collect()
}

fn validate_wordlist(contents: &str, wordlist_path: &Path) -> Result<()> {
    let line_count = contents.lines().count();
    if line_count != EXPECTED_WORDLIST_LINES {
        return Err(PasswordGeneratorError::WordlistValidation(format!(
            "Expected {} entries in {}, found {}",
            EXPECTED_WORDLIST_LINES,
            wordlist_path.display(),
            line_count
        )));
    }

    let checksum = format!("{:x}", Sha256::digest(contents.as_bytes()));
    let checksum_path = checksum_path(wordlist_path);

    if checksum_path.exists() {
        let stored = fs::read_to_string(&checksum_path)?.trim().to_string();
        if stored != checksum {
            return Err(PasswordGeneratorError::WordlistValidation(format!(
                "Checksum mismatch for {}. Delete the wordlist and rerun npwg to redownload.",
                wordlist_path.display()
            )));
        }
    } else {
        fs::write(&checksum_path, &checksum)?;
    }

    Ok(())
}

fn checksum_path(wordlist_path: &Path) -> PathBuf {
    wordlist_path
        .parent()
        .map(|parent| parent.join(DICEWARE_CHECKSUM_FILENAME))
        .unwrap_or_else(|| PathBuf::from(DICEWARE_CHECKSUM_FILENAME))
}
