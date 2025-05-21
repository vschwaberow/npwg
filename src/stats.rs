// SPDX-License-Identifier: MIT
// Project: npwg
// File: src/stats.rs
// Author: Volker Schwaberow <volker@schwaberow.de>
// Copyright (c) 2022 Volker Schwaberow

pub struct PasswordQuality {
    pub mean: f64,
    pub variance: f64,
    pub skewness: f64,
    pub kurtosis: f64,
}

pub fn show_stats(passwords: &[String]) -> PasswordQuality {
    let entropies: Vec<f64> = passwords
        .iter()
        .map(|s| calculate_entropy(s.as_str()))
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

    let skewness = if variance == 0.0 {
        0.0
    } else {
        entropies.iter().map(|&x| (x - mean).powi(3)).sum::<f64>() / (n * variance.powf(1.5))
    };

    let kurtosis = if variance == 0.0 {
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

    let length = password.len() as f64;

    char_count.values().fold(0.0, |acc, &count| {
        let p = count as f64 / length;
        acc - p * p.log2()
    })
}
