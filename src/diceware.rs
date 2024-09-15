// SPDX-License-Identifier: MIT
// Project: npwg
// File: src/diceware.rs
// Author: Volker Schwaberow <volker@schwaberow.de>
// Copyright (c) 2022 Volker Schwaberow

use crate::error::PasswordGeneratorError;
use crate::error::Result;
use dirs::home_dir;
use reqwest;
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;

const DICEWARE_FILENAME: &str = "diceware_wordlist.txt";
const DICEWARE_URL: &str = "https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt";

pub async fn get_wordlist() -> Result<Vec<String>> {
    let home = home_dir().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::NotFound, "Home directory not found")
    })?;
    let wordlist_path = home.join(".npwg").join(DICEWARE_FILENAME);

    if wordlist_path.exists() {
        let wordlist = std::fs::read_to_string(&wordlist_path)?;
        Ok(wordlist
            .lines()
            .filter_map(|line| line.split_once('\t'))
            .map(|(_, word)| word.to_string())
            .collect())
    } else {
        download_wordlist(&wordlist_path).await?;
        Err(PasswordGeneratorError::WordlistDownloaded)
    }
}

async fn download_wordlist(wordlist_path: &PathBuf) -> Result<()> {
    println!("Downloading wordlist from {}", DICEWARE_URL);

    let response = reqwest::get(DICEWARE_URL).await?.text().await?;
    fs::create_dir_all(wordlist_path.parent().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::NotFound, "Parent directory not found")
    })?)?;

    let mut file = File::create(wordlist_path)?;
    file.write_all(response.as_bytes())?;

    println!("Wordlist downloaded to {:?}", wordlist_path);
    Ok(())
}
