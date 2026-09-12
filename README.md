# npwg - Secure Password Generator

npwg is a secure password generator written in Rust. With npwg, you can easily generate strong and random passwords or passphrases to protect your online accounts.

Current release: **0.5.3**.

## Features

- Generate passwords with custom length and count
- Support various defined character sets
- Generate diceware passwords
- Generate pronounceable passwords
- Customizable password length, count, character sets, and separators
- Avoid repeating characters in passwords
- Display statistics about the generated passwords
- Show a local heuristic strength estimate for generated passwords (not NIST or zxcvbn)
- Enforce a minimum estimated entropy by regenerating until the threshold is met
- Exclude ambiguous characters with `--no-ambiguous`
- Append required digit/symbol characters to diceware passphrases with `--require`
- Choose EFF large/short wordlists or a custom `--wordlist` path
- Check generated secrets against Have I Been Pwned via k-anonymity (`--check-pwned`)
- Machine-readable output (`--json`, `--null`) for scripts and password-manager pipelines
- Shell completions for bash, zsh, and fish (`--completions`)
- Offline diceware via embedded EFF wordlists
- Rich patterns such as `{L:4}{D:2}-{word}`
- Optional TTY auto-clear with `--clear-after`
- Interactive mode for easy password generation
- Deterministic mode for password derivation from a master password and service

## Installation

### Using Cargo

If you have Rust and Cargo installed, you can install npwg using the following command:

```sh
cargo install npwg
```

This installs the latest crates.io release (currently 0.5.3). For the git tip:

```sh
cargo install --git https://github.com/vschwaberow/npwg.git
```

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
- `--avoid-repeating`: Avoid consecutive repeating characters in the password
- `--stats`: Show statistics about the generated passwords
- `--strength`: Show a local heuristic strength estimate (not a formal compliance check)
- `--min-entropy <BITS>`: Regenerate until estimated entropy reaches at least BITS (conflicts with `--seed`, `--deterministic`, `--mutate`)
- `--no-ambiguous`: Exclude ambiguous characters (`0 O o 1 l I |`) from the character pool
- `--check-pwned`: Reject secrets found in Have I Been Pwned (SHA-1 prefix only)
- `--json`: Print secrets as a JSON array on stdout
- `--null`: Print secrets NUL-separated on stdout
- `--completions <SHELL>`: Print bash/zsh/fish completion script and exit
- `--clear-after <SECS>`: Clear the TTY after SECS (conflicts with `--json`, `--null`, `--qr`)
- `-a, --allowed <CHARS>`: Sets the allowed characters [default: allprint]
- `--use-words`: Use diceware words instead of characters (EFF wordlists, SHA-256 pinned)
- `--require <CLASSES>`: With `--use-words`, append required classes (`digit`, `symbol`)
- `--wordlist-preset <PRESET>`: Diceware preset (`eff-large`, `eff-short`; default `eff-large`)
- `--wordlist <PATH>`: Custom diceware wordlist path (tab-separated or plain words)
- `-i, --interactive`: Start interactive console mode
- `--config <PATH>`: Path to a configuration file with defaults and profiles
- `--profile <NAME>`: Name of a profile from the configuration file
- `--policy <POLICY>`: Apply a built-in password policy (`windows-ad`, `pci-dss`, `nist-high`)
- `--separator <SEPARATOR>`: Sets the separator for diceware passphrases (single character or 'random')
- `--pronounceable`: Generate pronounceable passwords from allowed vowels and consonants
- `-p, --pattern <PATTERN>`: Pattern template (`L`/`D`/`S`, `{L:n}`/`{D:n}`/`{S:n}`, `{word}`, literals)
- `--mutate`: Mutate the passwords (`--copy` copies the mutated results)
- `--mutation-type <TYPE>`: Type of mutation to apply (omit for random)
- `--mutation-strength <STRENGTH>`: Strength of mutation [default: 1]
- `--lengthen <INCREASE>`: Increase the length of passwords during mutation
- `-s, --seed <SEED>`: Seed the RNG for reproducible output (testing only; insecure for real secrets)
- `--copy`: Copy the generated password to the clipboard
- `--qr`: Print the generated passwords as QR codes
- `--deterministic`: Generate passwords deterministically from a master password and service
- `--deterministic-version <VERSION>`: Required with `--deterministic`: `v1` for existing passwords, `v2` for new passwords
- `-S, --service <SERVICE>`: Service or context name used as salt for deterministic generation
- `-u, --username <USERNAME>`: Optional username for deterministic generation
- `--counter <COUNTER>`: Counter for deterministic generation [default: 1]
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

Require at least 80 bits of estimated entropy (regenerates as needed):

```sh
npwg --min-entropy 80 --length 20
```

Machine-readable output and shell completions:

```sh
npwg --json --count 3
npwg --null --count 2 | tr '\0' '\n'
npwg --completions bash > /etc/bash_completion.d/npwg
```

Clear the terminal a few seconds after showing a secret:

```sh
npwg --clear-after 10 --length 24
```

Copy freshly generated secrets to the clipboard (on Linux the helper reads stdin, holds for 45 seconds, then clears and exits):

```sh
npwg --copy
```

Render passwords as QR codes (one per password):

```sh
npwg --qr --count 2
```

#### Diceware Passphrases

EFF large and short wordlists are embedded (offline, SHA-256 verified). Generate six-word phrases separated by spaces:

```sh
npwg --use-words --length 6
```

Customise separators or request random punctuation between words:

```sh
npwg --use-words --separator "-" --length 5
npwg --use-words --separator random --length 7
```

Use the EFF short list, a custom wordlist, or append digit/symbol for site rules:

```sh
npwg --use-words --wordlist-preset eff-short --length 8
npwg --use-words --wordlist ./my-words.txt --length 6
npwg --use-words --require digit,symbol --length 6
```

Skip ambiguous characters and reject breached secrets:

```sh
npwg --no-ambiguous --length 20
npwg --check-pwned --length 24
```

#### Pronounceable and Pattern Modes

Create pronounceable strings that alternate consonants and vowels from the allowed character set:

```sh
npwg --pronounceable --length 10
```

Enforce structural patterns (L=letter, D=digit, S=symbol). Unfulfillable symbols error out:

```sh
npwg --pattern LLDDS --length 16
```

#### Mutation Workflow

Tweak existing passwords with mutations (omit `--mutation-type` for random) and optional lengthening:

```sh
npwg --mutate --mutation-type swap --mutation-strength 2 --lengthen 3
```

#### Deterministic Mode

For a new password, select version `v2`:

```sh
npwg --deterministic --deterministic-version v2 --service example.com --length 24
```

Include an optional username and counter to create distinct variants:

```sh
npwg --deterministic --deterministic-version v2 --service example.com --username alice --counter 2 --length 24
```

To reproduce a password from an earlier release, select `v1`:

```sh
npwg --deterministic --deterministic-version v1 --service example.com --length 24
```

The CLI requires an explicit version and has no default. Existing commands must add `--deterministic-version v1` to reproduce their previous passwords.
Version `v2` changes the derivation. A switch to `v2` requires a password change at the service.

Record the version, service, username, counter, length, and ordered alphabet for each password.
Keep the master password secret. The same inputs and version reproduce the same password.

Version `v1` preserves the previous salt format and UTF-8 byte counting, including its Unicode length behavior.
Its colon-separated salt can map different service and username pairs to the same password.
For example, service `a:b` with username `c` shares a salt with service `a` and username `b:c`.
Version `v1` now rejects alphabets with more than 256 entries instead of continuing without output.

Version `v2` separates each input field and counts Unicode scalar values (`char` in Rust).
It supports alphabets with up to `u32::MAX` entries. Both versions preserve alphabet order and duplicate entries.
Inputs are not normalized or trimmed. An absent username differs from an empty username in `v2`.

The library function `generate_deterministic_password(...)` remains a `v1` call.
For explicit selection, call `generate_deterministic_password_versioned(...)` with the same six arguments and a final `DeterministicVersion::V1` or `DeterministicVersion::V2` argument.
Both versions reject an empty alphabet. With a valid alphabet, library calls with length zero return an empty string without derivation.

<details>
<summary>Version 2 derivation format</summary>

The salt contains these fields in order. All integers use big-endian encoding.

| Field | Encoding |
|---|---|
| Version prefix | Eight bytes: `npwg:v2` followed by a zero byte |
| Service | UTF-8 byte length as `u64`, then UTF-8 bytes |
| Absent username | One zero byte |
| Present username | Byte `1`, UTF-8 byte length as `u64`, then UTF-8 bytes |
| Counter | `u32` |
| Block index | `u32`, starting at zero |

Both versions use Argon2id version `0x13`, 65,536 KiB memory, three iterations, parallelism one, and 64 output bytes per block.
The master password supplies the UTF-8 password bytes to Argon2id.

Version `v2` reads each block as sixteen big-endian `u32` values.
For alphabet size `n`, it accepts values less than `floor(2^32 / n) * n` and selects entry `value % n`.
It derives another block only if the requested character count is incomplete.

Fixed test vectors cover both versions, including Unicode and multiple blocks. The v2 vectors also cover a 257-entry alphabet.

</details>

Use interactive mode for guided password, passphrase, and mutation prompts. Pattern prompts use `L`/`D`/`S` templates (not literal strings); charset, policy, and profile stay on the CLI:

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

Use built-in policies for common compliance regimes; these enforce minimum length and character-set expectations before applying your overrides:

```sh
npwg --policy windows-ad
npwg --policy pci-dss --count 10
```

## Contributing

Contributions are welcome! If you find a bug or have a suggestion for improvement, please open an issue or submit a pull request.

When contributing Rust code, include only the SPDX license header at the top of each `*.rs` file—avoid additional inline or block comments elsewhere.

## License

This project is licensed under the [MIT License](LICENSE).
