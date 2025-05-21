use npwg::generator::generate_with_pattern;

fn main() {
    let available_chars: Vec<char> = "abcdefg".chars().collect();
    let pattern = "LDLS";
    let length = 10;
    let seed = None;
    
    match generate_with_pattern(pattern, &available_chars, length, seed) {
        Ok(password) => {
            println!("Password generated: {}", password);
            println!("Password length: {}", password.len());
            
            let all_valid = password.chars().all(|c| available_chars.contains(&c));
            println!("All characters valid: {}", all_valid);
            
            let contains_digits = password.chars().any(|c| c.is_ascii_digit());
            println!("Contains digits: {} (should be false)", contains_digits);
            
            assert!(all_valid, "Password should only contain valid characters");
            assert!(!contains_digits, "Password should not contain digits");
            println!("Tests passed!");
        },
        Err(e) => println!("Error: {:?}", e),
    }
}
