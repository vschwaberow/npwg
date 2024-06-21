# npwg - Secure Password Generator

npwg is a secure password generator written in Rust. With npwg, you can easily generate strong and random passwords to protect your online accounts.

## Features

- Generate passwords with custom length
- Support various character sets (digits, lowercase letters, uppercase letters, symbols)
- Allow excluding specific characters
- Allow forcing the inclusion of specific characters
- Generate multiple passwords at once
- Display statistics about the generated passwords

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
npwg [OPTIONS] [LENGTH]
```

### Options

- `-l, --length <usize>`: Set the length of the password (default: 8)
- `-a, --allowed <STRING>`: Set the allowed character sets (comma-separated) [default: digit,lowerletter,upperletter,symbol1,symbol2]
- `-e, --exclude <STRING>`: Exclude specific characters (comma-separated)
- `-i, --include <STRING>`: Force the inclusion of specific characters (comma-separated)
- `-n, --num <usize>`: Set the number of passwords to generate (default: 1)
- `-s, --stats`: Display statistics about the generated passwords
- `-r, --avoid-repeating`: Avoid repeating characters in the password
- `-d, --diceware`: Generate a password using the Diceware method
- `-w, --words <usize>`: Set the number of words to generate (default: 6)
- `-h, --help`: Display the help information
- `-V, --version`: Display the version information

### Examples

Generate a password with the default length (8 characters):

```sh
npwg -l 12
```

Generate a password that includes only digits and lowercase letters:

```sh
npwg -a digit,lowerletter
```

Generate a password that excludes specific characters:

```sh
npwg -e 0,O,l
```

Generate a password that forces the inclusion of specific characters:

```sh
npwg -i 1,2,3
```
Generate 5 passwords at once:

```sh
npwg -n 5
```

Generate a password with a custom length and character sets:

```sh
npwg -l 16 -a digit,lowerletter,upperletter,symbol1,symbol2
```

Display statistics about the generated password:

```sh
npwg -s
```

Generate a password using the Diceware method. If no diceware wordlist is in ~/.npwg, it will be automatically downloaded from the EFF website:

```sh
npwg -d
```

Generate a password using the Diceware method with a custom number of words. The default number of words is 6. The wordlist will be downloaded if it is not found in ~/.npwg:

```sh
npwg -d -w 8
```

## Contributing

Contributions are welcome! If you find a bug or have a suggestion for improvement, please open an issue or submit a pull request.

## License

This project is licensed under the [MIT License](LICENSE).



