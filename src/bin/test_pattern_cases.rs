use npwg::generator::generate_with_pattern;

fn main() {
    let test_cases = [
        ("LDLS", "abcdefg", 10),
        ("LSLD", "abcdefg123", 10),
        ("LSLD", "abcdefg123!@#", 10),
    ];

    println!("Testing generate_with_pattern with different scenarios:\n");

    for (i, (pattern, chars_str, length)) in test_cases.iter().enumerate() {
        let available_chars: Vec<char> = chars_str.chars().collect();
        let seed = Some(42u64);

        match generate_with_pattern(pattern, &available_chars, *length, seed) {
            Ok(password) => {
                println!(
                    "Test case {}: Pattern '{}', Chars '{}'",
                    i + 1,
                    pattern,
                    chars_str
                );
                println!("  - Password: {}", password);
                println!("  - Length: {}", password.len());
                println!(
                    "  - Contains digits: {}",
                    password.chars().any(|c| c.is_ascii_digit())
                );
                println!(
                    "  - Contains special: {}",
                    password.chars().any(|c| !c.is_ascii_alphanumeric())
                );

                let all_valid = password.chars().all(|c| available_chars.contains(&c));
                println!("  - All chars valid: {}", all_valid);
                assert!(all_valid, "Password should only contain valid characters");
                println!("  - Test passed\n");
            }
            Err(e) => println!("Error in test case {}: {:?}\n", i + 1, e),
        }
    }
}
