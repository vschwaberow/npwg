use npwg::generator::generate_with_pattern;

fn main() {
    let available_chars: Vec<char> = "abcdefg".chars().collect();
    let pattern = "LDLS";
    let length = 10;
    let seed = None;

    match generate_with_pattern(pattern, &available_chars, length, seed, false) {
        Ok(_) => {
            eprintln!("Expected pattern error for unfulfillable LDLS on abcdefg");
            std::process::exit(1);
        }
        Err(e) => {
            println!("Pattern correctly rejected: {:?}", e);
        }
    }
}
