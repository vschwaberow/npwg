// SPDX-License-Identifier: MIT
// Project: npwg
// File: src/pwned.rs
// Author: Volker Schwaberow <volker@schwaberow.de>
// Copyright (c) 2022 Volker Schwaberow

use crate::error::{PasswordGeneratorError, Result};
use reqwest::Client;
use sha1::{Digest, Sha1};
use std::time::Duration;
use zeroize::Zeroize;

const HIBP_RANGE_URL: &str = "https://api.pwnedpasswords.com/range/";
const HIBP_TIMEOUT: Duration = Duration::from_secs(15);

pub async fn ensure_secrets_not_pwned(secrets: &[String]) -> Result<()> {
    for secret in secrets {
        if is_pwned(secret).await? {
            return Err(PasswordGeneratorError::PwnedPassword(
                "Generated secret appears in the Have I Been Pwned database.".to_string(),
            ));
        }
    }
    Ok(())
}

async fn is_pwned(secret: &str) -> Result<bool> {
    let (prefix, suffix) = sha1_prefix_suffix(secret);
    let body = fetch_range(&prefix).await?;
    let found = range_contains_suffix(&body, &suffix);
    Ok(found)
}

fn sha1_prefix_suffix(secret: &str) -> (String, String) {
    let mut hasher = Sha1::new();
    hasher.update(secret.as_bytes());
    let mut digest = hasher.finalize();
    let hex = digest
        .iter()
        .map(|byte| format!("{:02X}", byte))
        .collect::<String>();
    digest.zeroize();
    let prefix = hex[..5].to_string();
    let suffix = hex[5..].to_string();
    (prefix, suffix)
}

async fn fetch_range(prefix: &str) -> Result<String> {
    let client = Client::builder().timeout(HIBP_TIMEOUT).build()?;
    let url = format!("{}{}", HIBP_RANGE_URL, prefix);
    let response = client
        .get(&url)
        .header("Add-Padding", "true")
        .send()
        .await?
        .error_for_status()?;
    Ok(response.text().await?)
}

pub fn range_contains_suffix(body: &str, suffix: &str) -> bool {
    let needle = suffix.to_ascii_uppercase();
    for line in body.lines() {
        let (hash_suffix, _) = match line.split_once(':') {
            Some(parts) => parts,
            None => continue,
        };
        if hash_suffix.eq_ignore_ascii_case(&needle) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha1_prefix_suffix_matches_known_vector() {
        // SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
        let (prefix, suffix) = sha1_prefix_suffix("password");
        assert_eq!(prefix, "5BAA6");
        assert_eq!(suffix, "1E4C9B93F3F0682250B6CF8331B7EE68FD8");
    }

    #[test]
    fn range_matcher_finds_suffix_case_insensitively() {
        let body = "0018A45C4D1DEF81644B54AB7F969B88D65:1\n\
                    1E4C9B93F3F0682250B6CF8331B7EE68FD8:3303003\n\
                    FFF:0\n";
        assert!(range_contains_suffix(
            body,
            "1e4c9b93f3f0682250b6cf8331b7ee68fd8"
        ));
        assert!(!range_contains_suffix(body, "DEADBEEF"));
    }
}
