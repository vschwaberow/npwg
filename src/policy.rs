// SPDX-License-Identifier: MIT
// Project: npwg
// File: src/policy.rs
// Author: Volker Schwaberow <volker@schwaberow.de>

use crate::config::{PasswordGeneratorConfig, Separator};
use crate::error::Result;
use crate::profile::apply_allowed_sets;
use clap::ValueEnum;

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum PolicyName {
    #[clap(alias = "windows", alias = "ad")]
    WindowsAd,
    #[clap(alias = "pci")]
    PciDss,
    #[clap(alias = "nist")]
    NistHigh,
}

pub struct PolicyDetails {
    pub label: &'static str,
    pub description: &'static str,
    pub minimum_length: usize,
    pub recommended_entropy_bits: f64,
}

pub fn apply_policy(
    policy: PolicyName,
    config: &mut PasswordGeneratorConfig,
) -> Result<PolicyDetails> {
    match policy {
        PolicyName::WindowsAd => apply_windows_ad(config),
        PolicyName::PciDss => apply_pci_dss(config),
        PolicyName::NistHigh => apply_nist_high(config),
    }
}

fn ensure_length(config: &mut PasswordGeneratorConfig, minimum: usize) {
    if config.length < minimum {
        config.length = minimum;
    }
}

fn ensure_separator(config: &mut PasswordGeneratorConfig) {
    if config.mode == crate::config::PasswordGeneratorMode::Diceware && config.separator.is_none() {
        config.separator = Some(Separator::Fixed(' '));
    }
}

fn apply_windows_ad(config: &mut PasswordGeneratorConfig) -> Result<PolicyDetails> {
    ensure_length(config, 14);
    apply_allowed_sets(config, "upperletter,lowerletter,digit,symbol2")?;
    config.set_avoid_repeating(false);
    config.pattern = None;
    config.pronounceable = false;
    config.mode = crate::config::PasswordGeneratorMode::Password;
    ensure_separator(config);
    Ok(PolicyDetails {
        label: "Windows Active Directory",
        description: "Requires 14+ characters including upper, lower, digits, and symbols.",
        minimum_length: 14,
        recommended_entropy_bits: 84.0,
    })
}

fn apply_pci_dss(config: &mut PasswordGeneratorConfig) -> Result<PolicyDetails> {
    ensure_length(config, 12);
    apply_allowed_sets(config, "upperletter,lowerletter,digit,symbol2")?;
    config.set_avoid_repeating(false);
    config.mode = crate::config::PasswordGeneratorMode::Password;
    ensure_separator(config);
    Ok(PolicyDetails {
        label: "PCI DSS",
        description: "Minimum 12 characters with mixed character classes per PCI DSS 4.0.",
        minimum_length: 12,
        recommended_entropy_bits: 72.0,
    })
}

fn apply_nist_high(config: &mut PasswordGeneratorConfig) -> Result<PolicyDetails> {
    ensure_length(config, 16);
    apply_allowed_sets(config, "upperletter,lowerletter,digit,symbol2")?;
    config.set_avoid_repeating(true);
    config.mode = crate::config::PasswordGeneratorMode::Password;
    ensure_separator(config);
    Ok(PolicyDetails {
        label: "NIST SP 800-63B High",
        description: "High assurance memorized secret guidance (16+ characters)",
        minimum_length: 16,
        recommended_entropy_bits: 96.0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PasswordGeneratorConfig;

    #[test]
    fn windows_policy_enforces_length_and_sets() {
        let mut config = PasswordGeneratorConfig::new();
        config.length = 8;
        let details = apply_policy(PolicyName::WindowsAd, &mut config).unwrap();
        assert_eq!(details.minimum_length, 14);
        assert!(config.length >= 14);
        assert!(config.allowed_chars.iter().any(|c| c.is_ascii_uppercase()));
        assert!(config
            .allowed_chars
            .iter()
            .any(|c| !c.is_ascii_alphanumeric()));
    }

    #[test]
    fn policy_can_raise_entropy_expectations() {
        let mut config = PasswordGeneratorConfig::new();
        let details = apply_policy(PolicyName::NistHigh, &mut config).unwrap();
        assert_eq!(details.recommended_entropy_bits as u32, 96);
        assert!(config.length >= 16);
    }
}
