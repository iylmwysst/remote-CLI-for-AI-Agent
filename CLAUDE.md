# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
cargo run -- --pin 123456          # run locally (note: -- before app flags)
cargo build                        # debug binary
cargo build --release              # optimized binary → target/release/codewebway
cargo test                         # run all tests
cargo fmt --all                    # format
cargo clippy --all-targets -- -D warnings  # lint (must pass before PRs)
```

## Architecture

**codewebway** is a Rust web terminal: it spawns PTY sessions and exposes them over WebSocket via an embedded web UI.

### Module responsibilities

| File | Role |
|------|------|
| `main.rs` | CLI parsing, startup sequencing, zrok lifecycle, signal/shutdown wiring |
| `config.rs` | `clap`-derived `Config` struct with all CLI flags |
| `server.rs` | Axum router, `AppState`, all HTTP/WS handlers, session/auth/temp-link/file logic |
| `session.rs` | PTY session (`SharedSession`), `Scrollback` ring-buffer, session spawning |
| `assets.rs` | `rust-embed` macro to bundle `assets/` at compile time |
| `build.rs` | Tells Cargo to rebuild when `assets/` changes |

### Key architectural patterns

**Authentication is two-factor**: a random token (auto-generated or `--password`) plus a PIN (`--pin`). Both are required at login. `FailedLoginTracker` locks out after 3 failures per 5 min window.

**Terminals** are named PTY sessions managed by `TerminalManager` (max 8 by default). The "main" terminal is created at startup; additional ones can be created via the REST API. Each terminal has a `Scrollback` ring-buffer (default 128 KB) replayed to new WebSocket subscribers.

**Sessions** (`SessionStore`) are token-authenticated HTTP sessions with idle (30 min) and absolute (12 h) timeouts. Auto-shutdown fires when no authenticated activity occurs within the 3-hour grace window — disabled when `--zrok --public-no-expiry` is combined.

**Temp links** are HMAC-signed URLs with configurable TTL (5/15/60 min), scope (`read-only` or `interactive`), and max-use count. At most 2 active at once. They bypass the normal login flow and grant a `TempSessionGrant`.

**zrok integration** (`--zrok`): spawns `zrok share public <port> --headless` as a child process. Ownership is tracked via a PID file in `$TMPDIR/codewebway/` so stale shares from prior crashes are reclaimed on startup.

**Static assets** (`assets/index.html`, `assets/favicon.svg`) are embedded into the binary via `rust-embed` and served with gzip/brotli compression via `tower-http`.

### Commit style

Prefixed imperative: `fix:`, `feat:`, `docs:`, `ux:`, `build:`. Keep commits atomic.
