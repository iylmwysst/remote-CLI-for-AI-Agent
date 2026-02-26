# codewebway Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a single Rust binary that exposes a shared PTY session over WebSocket + a browser terminal UI (xterm.js), accessible from any device on the same network/tunnel.

**Architecture:** axum handles HTTP and WebSocket upgrades; portable-pty spawns and manages a single cross-platform PTY; a tokio broadcast channel fans PTY output out to all connected WebSocket clients simultaneously; rust-embed bakes the xterm.js HTML into the binary at compile time.

**Tech Stack:** Rust 2021, axum 0.7, tokio 1 (full), portable-pty 0.8, rust-embed 8, clap 4, serde_json 1, bytes 1

---

### Task 1: Scaffold — Cargo.toml + directory structure

**Files:**
- Create: `Cargo.toml`
- Create: `src/main.rs`
- Create: `src/config.rs`
- Create: `src/session.rs`
- Create: `src/server.rs`
- Create: `src/assets.rs`
- Create: `assets/index.html`

**Step 1: Create Cargo.toml**

```toml
[package]
name = "codewebway"
version = "0.1.0"
edition = "2021"

[[bin]]
name = "codewebway"
path = "src/main.rs"

[dependencies]
axum = { version = "0.7", features = ["ws"] }
tokio = { version = "1", features = ["full"] }
portable-pty = "0.8"
rust-embed = "8"
clap = { version = "4", features = ["derive"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
bytes = "1"
tower-http = { version = "0.5", features = ["trace"] }
tracing = "0.1"
tracing-subscriber = "0.3"

[profile.release]
opt-level = 3
strip = true
lto = true
```

**Step 2: Create stub source files**

`src/main.rs`:
```rust
mod config;
mod session;
mod server;
mod assets;

#[tokio::main]
async fn main() {
    println!("codewebway stub");
}
```

`src/config.rs`, `src/session.rs`, `src/server.rs`, `src/assets.rs`: each just `// stub`

`assets/index.html`: `<!DOCTYPE html><html><body>stub</body></html>`

**Step 3: Verify it compiles**

```bash
cd /Users/Lab/codewebway
cargo build 2>&1 | tail -5
```
Expected: `Finished dev [unoptimized + debuginfo] target(s)`

**Step 4: Commit**

```bash
git add -A
git commit -m "chore: scaffold project structure"
```

---

### Task 2: Config — CLI parsing with clap

**Files:**
- Modify: `src/config.rs`
- Modify: `src/main.rs`

**Step 1: Write failing test**

Add to `src/config.rs`:
```rust
use clap::Parser;

#[derive(Parser, Debug, Clone)]
#[command(name = "codewebway", about = "Browser-accessible terminal over WebSocket")]
pub struct Config {
    /// Port to listen on
    #[arg(long, default_value_t = 8080)]
    pub port: u16,

    /// Shared secret password (required)
    #[arg(long)]
    pub password: String,

    /// Shell to spawn (default: $SHELL on Unix, cmd.exe on Windows)
    #[arg(long)]
    pub shell: Option<String>,

    /// Scrollback buffer size in bytes
    #[arg(long, default_value_t = 10240)]
    pub scrollback: usize,
}

impl Config {
    pub fn shell_path(&self) -> String {
        if let Some(s) = &self.shell {
            return s.clone();
        }
        #[cfg(windows)]
        {
            std::env::var("COMSPEC").unwrap_or_else(|_| "cmd.exe".to_string())
        }
        #[cfg(not(windows))]
        {
            std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_port() {
        let cfg = Config::parse_from(["codewebway", "--password", "secret"]);
        assert_eq!(cfg.port, 8080);
    }

    #[test]
    fn test_custom_port() {
        let cfg = Config::parse_from(["codewebway", "--password", "secret", "--port", "9090"]);
        assert_eq!(cfg.port, 9090);
    }

    #[test]
    fn test_password_stored() {
        let cfg = Config::parse_from(["codewebway", "--password", "mysecret"]);
        assert_eq!(cfg.password, "mysecret");
    }

    #[test]
    fn test_shell_override() {
        let cfg = Config::parse_from(["codewebway", "--password", "x", "--shell", "/bin/bash"]);
        assert_eq!(cfg.shell_path(), "/bin/bash");
    }

    #[test]
    fn test_shell_default_falls_back() {
        let cfg = Config::parse_from(["codewebway", "--password", "x"]);
        // just verify it returns something non-empty
        assert!(!cfg.shell_path().is_empty());
    }
}
```

**Step 2: Run tests — expect FAIL (won't compile yet)**

```bash
cargo test config 2>&1 | tail -10
```

**Step 3: Update main.rs to use config**

```rust
mod config;
mod session;
mod server;
mod assets;

use clap::Parser;
use config::Config;

#[tokio::main]
async fn main() {
    let cfg = Config::parse();
    println!("Listening on port {} with shell {}", cfg.port, cfg.shell_path());
}
```

**Step 4: Run tests — expect PASS**

```bash
cargo test config 2>&1 | tail -10
```
Expected: `test config::tests::... ok` (5 tests)

**Step 5: Commit**

```bash
git add src/config.rs src/main.rs
git commit -m "feat: add CLI config with clap"
```

---

### Task 3: Session — scrollback buffer logic

**Files:**
- Modify: `src/session.rs`

**Step 1: Write failing tests**

```rust
use std::collections::VecDeque;

pub struct Scrollback {
    buf: VecDeque<u8>,
    max: usize,
}

impl Scrollback {
    pub fn new(max: usize) -> Self {
        Self { buf: VecDeque::new(), max }
    }

    pub fn push(&mut self, data: &[u8]) {
        for &b in data {
            if self.buf.len() >= self.max {
                self.buf.pop_front();
            }
            self.buf.push_back(b);
        }
    }

    pub fn snapshot(&self) -> Vec<u8> {
        self.buf.iter().copied().collect()
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_push_and_snapshot() {
        let mut sb = Scrollback::new(100);
        sb.push(b"hello");
        assert_eq!(sb.snapshot(), b"hello");
    }

    #[test]
    fn test_max_capacity_evicts_oldest() {
        let mut sb = Scrollback::new(5);
        sb.push(b"123456789"); // 9 bytes into 5-byte buffer
        assert_eq!(sb.len(), 5);
        assert_eq!(sb.snapshot(), b"56789");
    }

    #[test]
    fn test_empty_snapshot() {
        let sb = Scrollback::new(100);
        assert_eq!(sb.snapshot(), b"");
    }

    #[test]
    fn test_exact_capacity() {
        let mut sb = Scrollback::new(3);
        sb.push(b"abc");
        assert_eq!(sb.len(), 3);
        sb.push(b"d");
        assert_eq!(sb.snapshot(), b"bcd");
    }
}
```

**Step 2: Run tests**

```bash
cargo test session 2>&1 | tail -10
```
Expected: 4 tests PASS

**Step 3: Commit**

```bash
git add src/session.rs
git commit -m "feat: add scrollback buffer"
```

---

### Task 4: Session — SharedSession with PTY lifecycle

**Files:**
- Modify: `src/session.rs`

**Step 1: Add SharedSession struct and spawn function**

Append to `src/session.rs` (after Scrollback):
```rust
use std::sync::{Arc, Mutex};
use std::io::Write;
use bytes::Bytes;
use tokio::sync::broadcast;
use portable_pty::{CommandBuilder, PtySize, native_pty_system};

pub struct SharedSession {
    pub scrollback: Scrollback,
    pub tx: broadcast::Sender<Bytes>,
    pub pty_writer: Box<dyn Write + Send>,
}

pub type Session = Arc<Mutex<SharedSession>>;

pub fn spawn_session(shell: &str, scrollback_size: usize) -> anyhow::Result<Session> {
    let pty_system = native_pty_system();
    let pair = pty_system.openpty(PtySize {
        rows: 24,
        cols: 80,
        pixel_width: 0,
        pixel_height: 0,
    })?;

    let mut cmd = CommandBuilder::new(shell);
    cmd.env("TERM", "xterm-256color");
    let _child = pair.slave.spawn_command(cmd)?;

    let (tx, _) = broadcast::channel::<Bytes>(256);
    let pty_writer = pair.master.take_writer()?;

    let session = Arc::new(Mutex::new(SharedSession {
        scrollback: Scrollback::new(scrollback_size),
        tx: tx.clone(),
        pty_writer,
    }));

    // PTY reader thread
    let mut reader = pair.master.try_clone_reader()?;
    let session_clone = Arc::clone(&session);
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            match reader.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let data = Bytes::copy_from_slice(&buf[..n]);
                    let mut s = session_clone.lock().unwrap();
                    s.scrollback.push(&data);
                    let _ = s.tx.send(data);
                }
            }
        }
    });

    Ok(session)
}
```

Also add at top of file:
```rust
use std::io::Read;
```

**Step 2: Add anyhow to Cargo.toml**

```toml
anyhow = "1"
```

**Step 3: Verify compiles**

```bash
cargo build 2>&1 | tail -10
```
Expected: no errors

**Step 4: Commit**

```bash
git add src/session.rs Cargo.toml
git commit -m "feat: add SharedSession with PTY spawn and reader thread"
```

---

### Task 5: Assets — embed index.html

**Files:**
- Modify: `src/assets.rs`
- Modify: `assets/index.html`

**Step 1: Write assets.rs**

```rust
use rust_embed::Embed;

#[derive(Embed)]
#[folder = "assets/"]
pub struct Assets;
```

**Step 2: Write assets/index.html**

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>codewebway</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/xterm@5.3.0/css/xterm.min.css" />
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { background: #1e1e1e; display: flex; flex-direction: column; height: 100vh; }
    #terminal { flex: 1; padding: 4px; }
    #status { background: #333; color: #aaa; font-family: monospace; font-size: 12px; padding: 2px 8px; }
  </style>
</head>
<body>
  <div id="status">Connecting...</div>
  <div id="terminal"></div>

  <script src="https://cdn.jsdelivr.net/npm/xterm@5.3.0/lib/xterm.min.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/xterm-addon-fit@0.8.0/lib/xterm-addon-fit.min.js"></script>
  <script>
    const term = new Terminal({ cursorBlink: true, theme: { background: '#1e1e1e' } });
    const fitAddon = new FitAddon.FitAddon();
    term.loadAddon(fitAddon);
    term.open(document.getElementById('terminal'));
    fitAddon.fit();

    const status = document.getElementById('status');
    const token = new URLSearchParams(window.location.search).get('token') || '';
    const wsUrl = `${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/ws?token=${encodeURIComponent(token)}`;

    let ws;
    let retries = 0;

    function connect() {
      ws = new WebSocket(wsUrl);
      ws.binaryType = 'arraybuffer';

      ws.onopen = () => {
        status.textContent = 'Connected';
        status.style.color = '#4caf50';
        retries = 0;
      };

      ws.onmessage = (e) => {
        if (typeof e.data === 'string') {
          // JSON control message
          const msg = JSON.parse(e.data);
          if (msg.type === 'shell_exit') {
            status.textContent = 'Shell exited — refresh to reconnect';
            status.style.color = '#f44336';
          }
        } else {
          term.write(new Uint8Array(e.data));
        }
      };

      ws.onclose = () => {
        status.textContent = `Disconnected — retrying (${retries + 1})...`;
        status.style.color = '#ff9800';
        if (retries < 5) {
          retries++;
          setTimeout(connect, Math.min(1000 * retries, 5000));
        } else {
          status.textContent = 'Connection failed. Reload to retry.';
        }
      };

      ws.onerror = () => ws.close();
    }

    term.onData((data) => {
      if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(new TextEncoder().encode(data));
      }
    });

    window.addEventListener('resize', () => {
      fitAddon.fit();
      if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: 'resize', cols: term.cols, rows: term.rows }));
      }
    });

    connect();
  </script>
</body>
</html>
```

**Step 3: Verify compiles**

```bash
cargo build 2>&1 | tail -10
```

**Step 4: Commit**

```bash
git add src/assets.rs assets/index.html
git commit -m "feat: embed xterm.js HTML as static asset"
```

---

### Task 6: Server — HTTP routes + WebSocket auth

**Files:**
- Modify: `src/server.rs`
- Modify: `src/main.rs`

**Step 1: Write auth helper test**

Add to `src/server.rs`:
```rust
/// Returns true if the token matches the password (constant-time compare).
pub fn check_token(token: &str, password: &str) -> bool {
    // Use constant-time comparison to avoid timing attacks
    if token.len() != password.len() {
        return false;
    }
    token.as_bytes().iter().zip(password.as_bytes()).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_correct_token() {
        assert!(check_token("secret", "secret"));
    }

    #[test]
    fn test_wrong_token() {
        assert!(!check_token("wrong", "secret"));
    }

    #[test]
    fn test_empty_token() {
        assert!(!check_token("", "secret"));
    }

    #[test]
    fn test_token_length_mismatch() {
        assert!(!check_token("sec", "secret"));
    }
}
```

**Step 2: Run auth tests**

```bash
cargo test server 2>&1 | tail -10
```
Expected: 4 tests PASS

**Step 3: Write full server.rs**

```rust
use axum::{
    extract::{Query, State, WebSocketUpgrade},
    extract::ws::{Message, WebSocket},
    response::{Html, IntoResponse, Response},
    routing::get,
    Router,
};
use bytes::Bytes;
use serde::Deserialize;
use std::sync::Arc;
use tokio::sync::broadcast;

use crate::assets::Assets;
use crate::session::Session;

#[derive(Clone)]
pub struct AppState {
    pub session: Session,
    pub password: String,
}

#[derive(Deserialize)]
pub struct WsQuery {
    token: Option<String>,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(serve_index))
        .route("/ws", get(ws_handler))
        .with_state(Arc::new(state))
}

async fn serve_index() -> impl IntoResponse {
    let html = Assets::get("index.html").unwrap();
    Html(std::str::from_utf8(html.data.as_ref()).unwrap().to_string())
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    Query(q): Query<WsQuery>,
    State(state): State<Arc<AppState>>,
) -> Response {
    let token = q.token.unwrap_or_default();
    if !check_token(&token, &state.password) {
        return (axum::http::StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
    }
    ws.on_upgrade(move |socket| handle_socket(socket, state))
}

async fn handle_socket(mut socket: WebSocket, state: Arc<AppState>) {
    // Send scrollback
    let (scrollback, mut rx) = {
        let s = state.session.lock().unwrap();
        (s.scrollback.snapshot(), s.tx.subscribe())
    };
    if !scrollback.is_empty() {
        let _ = socket.send(Message::Binary(scrollback.into())).await;
    }

    loop {
        tokio::select! {
            // PTY output → browser
            result = rx.recv() => {
                match result {
                    Ok(data) => {
                        if socket.send(Message::Binary(data.to_vec().into())).await.is_err() {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(_) => break,
                }
            }
            // Browser input → PTY
            result = socket.recv() => {
                match result {
                    Some(Ok(Message::Binary(data))) => {
                        let mut s = state.session.lock().unwrap();
                        let _ = s.pty_writer.write_all(&data);
                    }
                    Some(Ok(Message::Text(text))) => {
                        // Handle resize JSON
                        if let Ok(msg) = serde_json::from_str::<serde_json::Value>(&text) {
                            if msg["type"] == "resize" {
                                let cols = msg["cols"].as_u64().unwrap_or(80) as u16;
                                let rows = msg["rows"].as_u64().unwrap_or(24) as u16;
                                // portable-pty resize via stored handle would go here
                                // For now: no-op (resize support added in Task 7)
                                let _ = (cols, rows);
                            }
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    _ => {}
                }
            }
        }
    }
}

pub fn check_token(token: &str, password: &str) -> bool {
    if token.len() != password.len() {
        return false;
    }
    token.as_bytes().iter().zip(password.as_bytes()).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_correct_token() {
        assert!(check_token("secret", "secret"));
    }

    #[test]
    fn test_wrong_token() {
        assert!(!check_token("wrong", "secret"));
    }

    #[test]
    fn test_empty_token() {
        assert!(!check_token("", "secret"));
    }

    #[test]
    fn test_token_length_mismatch() {
        assert!(!check_token("sec", "secret"));
    }
}
```

Add `use std::io::Write;` at the top.

**Step 4: Wire up main.rs**

```rust
mod config;
mod session;
mod server;
mod assets;

use clap::Parser;
use config::Config;
use server::AppState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let cfg = Config::parse();

    if cfg.password.is_empty() {
        eprintln!("Error: --password is required");
        std::process::exit(1);
    }

    let session = session::spawn_session(&cfg.shell_path(), cfg.scrollback)?;

    let state = AppState {
        session,
        password: cfg.password.clone(),
    };

    let app = server::router(state);
    let addr = format!("0.0.0.0:{}", cfg.port);
    println!("codewebway listening on http://{}", addr);
    println!("Connect: http://{}/?token={}", addr, cfg.password);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
```

**Step 5: Build and run tests**

```bash
cargo build 2>&1 | tail -10
cargo test 2>&1 | tail -20
```
Expected: all tests PASS, binary compiles

**Step 6: Smoke test manually**

```bash
cargo run -- --password test123
# open browser: http://localhost:8080/?token=test123
```
Expected: terminal appears in browser, shell responds to input

**Step 7: Commit**

```bash
git add src/server.rs src/main.rs
git commit -m "feat: add axum server with WebSocket handler and auth"
```

---

### Task 7: PTY resize support

**Files:**
- Modify: `src/session.rs`
- Modify: `src/server.rs`

**Step 1: Store PtyMaster in SharedSession**

In `session.rs`, change `SharedSession` to also keep the `master` handle for resize:

```rust
pub struct SharedSession {
    pub scrollback: Scrollback,
    pub tx: broadcast::Sender<Bytes>,
    pub pty_writer: Box<dyn Write + Send>,
    pub pty_master: Box<dyn portable_pty::MasterPty + Send>,
}
```

Update `spawn_session` to store `pair.master` (after taking writer):
```rust
let pty_writer = pair.master.take_writer()?;
// pair.master is now the master handle
let session = Arc::new(Mutex::new(SharedSession {
    scrollback: Scrollback::new(scrollback_size),
    tx: tx.clone(),
    pty_writer,
    pty_master: pair.master,  // move master here
}));
```

**Step 2: Wire resize in server.rs**

Replace the `// no-op` resize block in `handle_socket`:
```rust
let _ = {
    let mut s = state.session.lock().unwrap();
    s.pty_master.resize(portable_pty::PtySize {
        rows,
        cols,
        pixel_width: 0,
        pixel_height: 0,
    })
};
```

**Step 3: Build**

```bash
cargo build 2>&1 | tail -10
```
Expected: compiles without errors

**Step 4: Commit**

```bash
git add src/session.rs src/server.rs
git commit -m "feat: implement PTY resize on browser window resize"
```

---

### Task 8: Release build + final smoke test

**Step 1: Build release binary**

```bash
cargo build --release 2>&1 | tail -5
ls -lh target/release/codewebway
```
Expected: binary under 10 MB

**Step 2: Run all tests one final time**

```bash
cargo test 2>&1
```
Expected: all tests PASS, zero failures

**Step 3: Final smoke test**

```bash
./target/release/codewebway --password hello123
# open http://localhost:8080/?token=hello123
# verify: terminal renders, typing works, resize works
```

**Step 4: Tag**

```bash
git add -A
git commit -m "chore: verify release build" --allow-empty
git tag v0.1.0
```

---

## Summary

| Task | Component | Tests |
|------|-----------|-------|
| 1 | Scaffold | build check |
| 2 | CLI config | 5 unit tests |
| 3 | Scrollback buffer | 4 unit tests |
| 4 | PTY spawn + reader | build check |
| 5 | Embedded HTML | build check |
| 6 | Server + auth + WebSocket | 4 unit tests + smoke |
| 7 | PTY resize | build check |
| 8 | Release build | full test suite |
