# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Added
- Regression tests covering pronounceable output, mutation workflows, clipboard failures, and CLI argument parsing.
- Explicit error variants for wordlist validation failures and clipboard availability.

### Changed
- GitHub Actions release workflow now publishes `npwg` binaries directly.
- Diceware downloads apply network timeouts, checksum validation, and clearer recovery guidance.
- Clipboard integration surfaces actionable errors and rejects empty copy requests.
- README usage examples consolidated with dedicated pattern and mutation sections.
- Dependency stack refreshed to latest patch releases (reqwest, arboard, openssl, etc.).

## [0.4.5] - 2025-05-21
### Added
- Pattern validation utilities (`src/bin/test_pattern*.rs`) and extensive async tests that exercise generator edge cases.
- Richer mutation tooling with optional mutation-type overrides, configurable strength, and clearer output formatting.
### Changed
- Password, diceware, and pronounceable generators now propagate errors consistently to the CLI layer.
- Strength and statistics reporting refined to deliver clearer feedback and improvement suggestions.
### Fixed
- Resolved silent failure cases when generation encountered invalid configuration or clipboard access errors.

## [0.4.4] - 2025-02-26
### Added
- Improvement suggestions for weak and moderate passwords directly in the strength meter output.
### Changed
- Strength evaluation internals tuned for more accurate scoring and user guidance.
### Fixed
- Updated dependency stack and tightened workflow permissions to address security alerts.

## [0.4.3] - 2025-02-23
### Added
- Dedicated `interactive` module that encapsulates the interactive CLI flow and supporting helpers.
### Changed
- Streamlined the main binary by moving interactive logic into the new module and cleaning unused imports.

## [0.4.2] - 2025-02-11
### Changed
- Adjusted GitHub Actions release workflow and refreshed dependency versions for stability.
### Fixed
- Resolved CI permissions and ensured build artifacts publish correctly across platforms.

## [0.4.1] - 2025-01-28
### Added
- Optional `--seed` flag wiring to allow deterministic password generation for testing and reproducibility.
### Changed
- Upgraded the randomness stack (`rand`, `rand_distr`) and runtime dependencies (`tokio`, `dirs`, `colored`, `thiserror`, `serde`, `reqwest`) to latest releases.

## [0.4.0] - 2024-12-24
### Added
- Pattern-driven password generation mode enabling templates such as `LLDDS` for precise control over character classes.
### Changed
- Updated dependency tree after introducing pattern support.

## [0.3.7] - 2024-11-16
### Changed
- Routine dependency refresh across networking, regex, and error-handling crates to maintain security posture.

## [0.3.6] - 2024-10-11
### Added
- Clipboard daemonization on Linux to ensure copies persist after the CLI exits.
### Changed
- Swapped the clipboard backend to `arboard` for better cross-platform support and improved error handling.

## [0.3.5] - 2024-10-09
### Added
- Password strength meter (`--strength`) with entropy scoring and guidance.
- Password mutation modes, including lengthening, replacements, and interactive previews.
- Clipboard integration for copying generated secrets directly from the CLI.
### Changed
- Expanded tests around configuration parsing and generation routines.
- Updated documentation to cover the new strength and mutation flows.

## [0.3.4] - 2024-10-04
### Added
- Initial strength analysis module and mutation helpers for password tweaking.
- Additional configuration tests improving coverage of character set handling.
### Changed
- Refined CLI help text and README examples for the new features.

## [0.3.3] - 2024-09-23
### Added
- Pronounceable password generator mode and optimizations to diceware passphrase creation.
### Changed
- CLI wiring to expose the new generation modes.

## [0.3.2] - 2024-09-15
### Added
- Configurable diceware separators (explicit character or random) with accompanying docs.
### Changed
- Diceware configuration to honour the separator option across outputs.

## [0.3.1] - 2024-09-10
### Changed
- Dependency refresh across `clap`, `dashmap`, and `serde`.

## [0.3.0] - 2024-09-03
### Added
- Interactive console mode built with `dialoguer`, enabling guided password generation.

## [0.2.7] - 2024-08-31
### Added
- Optional avoidance of repeating characters and improved diceware passphrase assembly.
- Automatic diceware wordlist download via `reqwest` when missing.
### Changed
- General password generation tuning and dependency updates.

## [0.2.6] - 2024-08-23
### Added
- Library-friendly API surface in `lib.rs` exposing generation helpers to external consumers.

## [0.2.5] - 2024-08-20
### Changed
- Dependency maintenance across `tokio`, `clap`, `serde`, and `reqwest` crates.

## [0.2.4] - 2024-08-13
### Changed
- Continued dependency updates (clap, serde, regex, tokio, thiserror, openssl) alongside CI workflow tweaks.

## [0.2.3] - 2024-07-09
### Changed
- Updated `serde` dependency to the latest patch release.

## [0.2.2] - 2024-07-01
### Added
- Diceware wordlist download and caching plus improved error reporting throughout generation flows.
### Changed
- Configuration revamped to build character sets from predefined definitions; dependency updates across the stack.

## [0.2.1] - 2024-06-21
### Changed
- README refreshed to document the expanding feature set.

## [0.2.0] - 2024-06-20
### Added
- Diceware passphrase generation in both CLI and library layers.
- Async/await refactor for password and diceware generation functions.
### Changed
- Dependency upgrades to support async workflows and diceware support.

## [0.1.6] - 2024-06-07
### Added
- Dependabot automation for cargo dependencies.
### Changed
- Updated runtime dependencies (`tokio`, `zeroize`) and crate metadata.

## [0.1.5] - 2024-04-14
### Added
- Repository metadata to `Cargo.toml` for crates.io visibility.

## [0.1.4] - 2024-04-14
### Fixed
- Corrected default CLI values after initial feedback.

## [0.1.3] - 2024-04-14
### Added
- `--avoid-repeating` flag and extended character set options with OS RNG support.
### Changed
- Dependency updates accompanying the new CLI knobs.

## [0.1.2] - 2024-04-13
### Added
- Additional predefined character sets and build workflow improvements.

## [0.1.0] - 2024-04-12
### Added
- Initial release of `npwg` with configurable secure password generation via CLI.
