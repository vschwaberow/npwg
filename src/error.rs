// SPDX-License-Identifier: MIT
// Project: npwg
// File: src/error.rs
// Author: Volker Schwaberow <volker@schwaberow.de>
// Copyright (c) 2022 Volker Schwaberow

use dialoguer::Error as DialoguerError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PasswordGeneratorError {
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),
    #[error("Wordlist downloaded, restart the program to use it.")]
    WordlistDownloaded,
    #[error("Wordlist validation failed: {0}")]
    WordlistValidation(String),
    #[error("Configuration error: {0}")]
    ConfigFile(String),
    #[error("Dialoguer error: {0}")]
    DialoguerError(DialoguerError),
    #[error("QR code error: {0}")]
    QrCode(String),
    #[error("{0}")]
    ClipboardError(String),
    #[error("Clipboard unavailable: {0}")]
    ClipboardUnavailable(String),
    #[error("KDF error: {0}")]
    KdfError(String),
}

impl From<DialoguerError> for PasswordGeneratorError {
    fn from(error: DialoguerError) -> Self {
        PasswordGeneratorError::DialoguerError(error)
    }
}

pub type Result<T> = std::result::Result<T, PasswordGeneratorError>;
