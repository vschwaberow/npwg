// SPDX-License-Identifier: MIT
// Project: npwg
// File: src/error.rs
// Author: Volker Schwaberow <volker@schwaberow.de>
// Copyright (c) 2022 Volker Schwaberow

use thiserror::Error;

#[derive(Error, Debug)]
pub enum PasswordGeneratorError {
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),
    #[error("Worldlist downloaded, restart the program to use it.")]
    WordlistDownloaded,
}

pub type Result<T> = std::result::Result<T, PasswordGeneratorError>;
