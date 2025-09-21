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

### Example Recipes

#### Quick Passwords

Generate default credentials:

```sh
npwg
```

Specify length, count, and character sets:

```sh
npwg --length 20 --count 3 --allowed upperletter,lowerletter,digit
```

Inspect entropy and statistics in one pass:

```sh
npwg --strength --stats
```

Copy freshly generated secrets to the clipboard:

```sh
npwg --copy
```

#### Diceware Passphrases

First run downloads and verifies the EFF wordlist automatically. Generate six-word phrases separated by spaces:

```sh
npwg --use-words --length 6
```

Customise separators or request random punctuation between words:

```sh
npwg --use-words --separator "-" --length 5
npwg --use-words --separator random --length 7
```

#### Pronounceable and Pattern Modes

Create pronounceable strings that alternate consonants and vowels:

```sh
npwg --pronounceable --length 10
```

Enforce structural patterns (L=letter, D=digit, S=symbol):

```sh
npwg --pattern LLDDS --length 16
```

#### Mutation Workflow

Tweak existing passwords by applying deterministic mutations and optional lengthening:

```sh
npwg --mutate --mutation-type swap --mutation-strength 2 --lengthen 3
```

Use interactive mode for guided generation and mutation prompts:

```sh
npwg --interactive
```

### Configuration Profiles

Create a `config.toml` in `~/.config/npwg/` (or `~/.npwg/` on systems without XDG directories) to store defaults and reusable profiles:

```toml
[defaults]
length = 20
allowed = "upperletter,lowerletter,digit"

[profiles.work]
count = 5
use_words = true
separator = "-"
```

Invoke a profile at runtime:

```sh
npwg --profile work
```

Provide a custom config path when needed:

```sh
npwg --config ./fixtures/npwg.toml --profile personal
```

## Contributing

Contributions are welcome! If you find a bug or have a suggestion for improvement, please open an issue or submit a pull request.

When contributing Rust code, include only the SPDX license header at the top of each `*.rs` file—avoid additional inline or block comments elsewhere.

## License

This project is licensed under the [MIT License](LICENSE).
