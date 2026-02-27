# Repository Guidelines

## Project Structure & Module Organization
- `src/` contains all Rust source modules:
- `main.rs` wires CLI/config, startup, and server boot.
- `server.rs` handles HTTP/WebSocket routes and terminal/session behavior.
- `config.rs` defines CLI flags and validation.
- `session.rs` contains session lifecycle logic.
- `assets.rs` embeds static files.
- `assets/` stores web UI files (`index.html`, `favicon.svg`) embedded at build time.
- `dist/` is for distributable artifacts; runtime binaries are produced in `target/` by Cargo.
- `build.rs` tracks asset changes so rebuilds include updated embedded UI.

## Build, Test, and Development Commands
- `cargo run -- --pin 123456`: run locally with CLI args (note `--` before app flags).
- `cargo build`: compile debug binary.
- `cargo build --release`: produce optimized binary at `target/release/codewebway`.
- `cargo test`: run unit tests (mostly inline `#[cfg(test)]` modules in `src/*.rs`).
- `cargo fmt --all`: format code.
- `cargo clippy --all-targets -- -D warnings`: lint and fail on warnings before PRs.

## Coding Style & Naming Conventions
- Follow Rust 2021 defaults and keep formatting `rustfmt`-clean (4-space indentation, trailing commas where appropriate).
- Use `snake_case` for functions/modules/files, `CamelCase` for structs/enums, and `SCREAMING_SNAKE_CASE` for constants.
- Keep modules focused: prefer extending existing domain files (`config`, `session`, `server`) over creating broad utility dumps.
- Use explicit, descriptive CLI/help text when adding `clap` options.

## Testing Guidelines
- Place unit tests near implementation in `#[cfg(test)] mod tests` blocks.
- Name tests by behavior, e.g., `test_temp_link_defaults`, `test_custom_port`.
- Cover CLI parsing, auth/session edge cases, and temporary-link expiration/limits when relevant.
- Run `cargo test` locally before pushing; add regression tests for every bug fix.

## Commit & Pull Request Guidelines
- Match existing history style: prefixed, imperative commits such as `fix: ...`, `feat: ...`, `docs: ...`, `ux: ...`, `build: ...`.
- Keep commits scoped and atomic; avoid mixing refactors with behavior changes.
- PR checklist: clear problem/solution summary, test evidence (`cargo test`, plus `clippy`/`fmt` when relevant), linked issue (if available), and screenshots or terminal snippets for UI/UX-facing changes.

## Release Process
- Bump version in `Cargo.toml` (for example `0.3.15` -> `0.3.16`).
- Run release checks before publishing:
  - `cargo fmt --all`
  - `cargo test`
- Commit release changes with a scoped message, then create and push tag:
  - `git add Cargo.toml src/...`
  - `git commit -m "fix: ..."` (or `feat: ...`, `build: ...`)
  - `git tag -a vX.Y.Z -m "vX.Y.Z"`
  - `git push origin main`
  - `git push origin vX.Y.Z`
- Create GitHub release:
  - `gh release create vX.Y.Z --title "vX.Y.Z" --generate-notes`
- Upload binary assets required by installer (`install.sh` checks asset `name`, not label):
  - macOS Intel: `codewebway-x86_64-apple-darwin`
  - macOS Apple Silicon: `codewebway-aarch64-apple-darwin`
  - Linux x86_64 musl: `codewebway-x86_64-unknown-linux-musl`
  - Linux aarch64 musl: `codewebway-aarch64-unknown-linux-musl`
- Example upload command:
  - `gh release upload vX.Y.Z target/release/codewebway-x86_64-apple-darwin --clobber`
- Verify release assets after upload:
  - `gh release view vX.Y.Z --json assets,url`
