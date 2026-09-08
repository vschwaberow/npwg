// SPDX-License-Identifier: MIT
// Project: npwg
// File: src/stats.rs
// Author: Volker Schwaberow <volker@schwaberow.de>
// Copyright (c) 2022 Volker Schwaberow

use colored::Colorize;

pub struct PasswordQuality {
    pub mean: f64,
    pub variance: f64,
    pub skewness: f64,
    pub kurtosis: f64,
}

pub fn show_stats<S: AsRef<str>>(passwords: &[S]) -> PasswordQuality {
    let entropies: Vec<f64> = passwords
        .iter()
        .map(|s| calculate_entropy(s.as_ref()))
        .collect();
    let n = entropies.len() as f64;

    if n == 0.0 {
        return PasswordQuality {
            mean: 0.0,
            variance: 0.0,
            skewness: 0.0,
            kurtosis: 0.0,
        };
    }

    let mean = entropies.iter().sum::<f64>() / n;
    let variance = entropies.iter().map(|&x| (x - mean).powi(2)).sum::<f64>() / n;

    let skewness = if variance < 1e-10 {
        0.0
    } else {
        entropies.iter().map(|&x| (x - mean).powi(3)).sum::<f64>() / (n * variance.powf(1.5))
    };

    let kurtosis = if variance < 1e-10 {
        -3.0
    } else {
        (entropies.iter().map(|&x| (x - mean).powi(4)).sum::<f64>() / (n * variance.powi(2))) - 3.0
    };

    PasswordQuality {
        mean,
        variance,
        skewness,
        kurtosis,
    }
}
fn calculate_entropy(password: &str) -> f64 {
    let char_count: std::collections::HashMap<char, u32> =
        password
            .chars()
            .fold(std::collections::HashMap::new(), |mut acc, c| {
                *acc.entry(c).or_insert(0) += 1;
                acc
            });

    let length = password.chars().count() as f64;

    char_count.values().fold(0.0, |acc, &count| {
        let p = count as f64 / length;
        acc - p * p.log2()
    })
}

pub fn print_stats<S: AsRef<str>>(data: &[S]) {
    print_stats_to(data, false);
}

pub fn print_stats_to<S: AsRef<str>>(data: &[S], to_stderr: bool) {
    let pq = show_stats(data);
    let lines = [
        format!("\n{}", "Statistics:".blue().bold()),
        format!("Mean: {:.6}", pq.mean.to_string().yellow()),
        format!("Variance: {:.6}", pq.variance.to_string().yellow()),
        format!("Skewness: {:.6}", pq.skewness.to_string().yellow()),
        format!("Kurtosis: {:.6}", pq.kurtosis.to_string().yellow()),
    ];
    for line in lines {
        if to_stderr {
            eprintln!("{}", line);
        } else {
            println!("{}", line);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_uses_char_count_for_unicode() {
        // Four characters, eight UTF-8 bytes: probabilities must use char count.
        let unicode = "äöüß";
        assert_eq!(unicode.chars().count(), 4);
        assert_eq!(unicode.len(), 8);
        let entropy = calculate_entropy(unicode);
        // Four unique chars → Shannon entropy = 2.0 bits
        assert!((entropy - 2.0).abs() < 1e-9, "got {}", entropy);
    }
}
