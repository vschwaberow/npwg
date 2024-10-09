# npwg - Secure Password Generator

npwg is a secure password generator written in Rust. With npwg, you can easily generate strong and random passwords or passphrases to protect your online accounts.

## Features

- Generate passwords with custom length and count
- Support various defined character sets
- Generate diceware passwords
- Generate pronounceable passwords
- Customizable password length, count, character sets, and separators
- Avoid repeating characters in passwords
- Display statistics about the generated passwords
- Show the estimated strength of the generated passwords
- Interactive mode for easy password generation

## Installation

### Using Cargo

If you have Rust and Cargo installed, you can install npwg using the following command:

```sh
cargo install npwg
```

This will download and compile the latest version of npwg and install it in your Cargo binary directory.

### Manual Installation

1. Make sure you have Rust installed on your system. If not, you can download it from the official Rust website: [https://www.rust-lang.org/tools/install](https://www.rust-lang.org/tools/install)
2. Clone this repository:
   ```sh
   git clone https://github.com/vschwaberow/npwg.git
   ```
3. Navigate to the project directory:
   ```sh
   cd npwg
   ```
4. Build the project:
   ```sh
   cargo build --release
   ```
5. The executable can be found at `target/release/npwg`.

## Usage

```sh
npwg [OPTIONS]
```

### Options

- `-l, --length <LENGTH>`: Sets the length of the password [default: 16]
- `-c, --count <COUNT>`: Sets the number of passwords to generate [default: 1]
- `--avoid-repeating`: Avoid repeating characters in the password
- `--stats`: Show statistics about the generated passwords
- `--strength`: Show strength meter for the generated passwords
- `-a, --allowed <CHARS>`: Sets the allowed characters [default: allprint]
- `--use-words`: Use words instead of characters
- `-i, --interactive`: Start interactive console mode
- `--separator <SEPARATOR>`: Sets the separator for diceware passphrases (single character or 'random')
- `--pronounceable`: Generate pronounceable passwords
- `--mutate`: Mutate the passwords
- `--mutation-type <TYPE>`: Type of mutation to apply [default: replace]
- `--mutation-strength <STRENGTH>`: Strength of mutation [default: 1]
- `--lengthen <INCREASE>`: Increase the length of passwords during mutation
- `--copy`: Copy the generated password to the clipboard
- `-h, --help`: Print help
- `-V, --version`: Print version

### Predefined Character Sets

- `symbol1`, `symbol2`, `symbol3`: Different sets of symbols
- `digit`: Numeric digits
- `lowerletter`: Lowercase letters
- `upperletter`: Uppercase letters
- `shell`: Shell-safe characters
- `homoglyph1` to `homoglyph8`: Various homoglyph sets
- `slashes`, `brackets`, `punctuation`: Specific character types
- `all`, `allprint`, `allprintnoquote`, etc.: Various combinations of character types

### Examples

Use the interactive mode
```sh
npwg -i
```
or
```sh
npwg --interactive
```

Generate a password with the default length (16 characters):
```sh
npwg
```

Generate a password with a specific length:
```sh
npwg -l 12
```

Generate multiple passwords:
```sh
npwg -c 5
```

Generate a password using only uppercase and lowercase letters:
```sh
npwg -a upperletter,lowerletter
```

Generate a diceware passphrase:
```sh
npwg --use-words -l 6
```

Generate a diceware passphrase with a custom separator:
```sh
npwg --use-words --separator "-" -l 6
```

Generate a diceware passphrase with random separators:
```sh
npwg --use-words --separator random -l 6
```

Generate a pronounceable password:
```sh
npwg --pronounceable
```

Generate a password and display statistics:
```sh
npwg --stats
```

Generate a password and display the estimated strength:
```sh 
npwg --strength
```

Generate a password using the Diceware method. If no diceware wordlist is in ~/.npwg, it will be automatically downloaded from the EFF website:

```sh
npwg -d
```

Generate a password using the Diceware method with a custom number of words. The default number of words is 6. The wordlist will be downloaded if it is not found in ~/.npwg:

```sh
npwg -d -w 8
```

Generate a diceware passphrase with a custom separator:
```sh
npwg --use-words --separator "-" -l 6
```

Generate a diceware passphrase with random separators:
```sh
npwg --use-words --separator random -l 6
```

Mutate an existing password:
```sh
npwg --mutate --mutation-type replace --mutation-strength 3
```

Generate a password and copy it to the clipboard:
```sh
npwg --copy
```

## Contributing

Contributions are welcome! If you find a bug or have a suggestion for improvement, please open an issue or submit a pull request.

## License

This project is licensed under the [MIT License](LICENSE).