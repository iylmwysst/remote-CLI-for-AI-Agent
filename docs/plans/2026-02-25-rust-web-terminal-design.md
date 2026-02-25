# Rust Web Terminal — Design Document

**Date:** 2026-02-25
**Status:** Approved

## Problem Statement

Access a local terminal session from any browser (mobile, remote laptop) without installing
heavy remote-desktop software. The binary should be ultra-lightweight, carry its own web UI,
and rely on external network tunnels (Tailscale, ngrok) for exposure — not implement tunneling itself.

## Requirements

| # | Requirement |
|---|-------------|
| 1 | Single Rust binary — no runtime dependencies |
| 2 | Password authentication (shared secret via CLI flag) |
| 3 | Shared PTY session — all connected browsers see and interact with the same shell |
| 4 | Cross-platform PTY: macOS, Linux, Windows (ConPTY) |
| 5 | Shell auto-detected: `$SHELL` on Unix, `$COMSPEC` on Windows, overridable via `--shell` |
| 6 | Scrollback buffer replayed to new connections |
| 7 | WebSocket disconnect does NOT kill the running shell |
| 8 | HTML + xterm.js embedded in binary (no static file serving needed) |

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                  rust-webtty binary                 │
│                                                     │
│  ┌─────────────┐     ┌──────────────────────────┐  │
│  │  axum HTTP  │     │     PTY Manager           │  │
│  │  :8080      │     │  (portable-pty)           │  │
│  │             │     │                           │  │
│  │  GET /      │     │  one PtyPair              │  │
│  │  → HTML     │     │  + $SHELL / $COMSPEC      │  │
│  │             │     │                           │  │
│  │  GET /ws    │     │  reader thread            │  │
│  │  → WebSocket│────▶│  → broadcast tx (tokio)  │  │
│  └─────────────┘     └──────────────────────────┘  │
│                                                     │
│  ┌─────────────────────────────────────────────┐   │
│  │  SharedSession (Arc<Mutex<...>>)             │   │
│  │  - broadcast::Sender<Bytes>                  │   │
│  │  - PTY writer (Box<dyn Write>)               │   │
│  │  - scrollback: VecDeque<u8> (max 10 KB)      │   │
│  └─────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────┘
         ▲ Tailscale / ngrok (external, not our concern)
```

## Data Flow

1. Browser opens `GET /` → receives embedded `index.html` (xterm.js inside)
2. Browser opens WebSocket `GET /ws?token=<password>`
3. Server validates token — wrong token closes socket immediately, no detail leaked
4. On success: send scrollback buffer bytes → subscribe `broadcast::Receiver`
5. PTY reader thread: reads PTY stdout → appends to scrollback → sends to `broadcast::Sender`
6. All subscribed WebSocket clients receive the same bytes simultaneously
7. Browser keypress → WebSocket message → server writes bytes to PTY stdin
8. Shell resize event → WebSocket sends `{"type":"resize","cols":N,"rows":M}` → server calls `pty.resize()`

## Crates

| Crate | Version | Purpose |
|-------|---------|---------|
| `axum` | 0.7 | HTTP server + WebSocket upgrade |
| `tokio` | 1 (full) | Async runtime, broadcast channel |
| `portable-pty` | 0.8 | Cross-platform PTY (macOS/Linux/Windows ConPTY) |
| `rust-embed` | 8 | Embed `index.html` into binary at compile time |
| `clap` | 4 | CLI argument parsing |
| `bytes` | 1 | Zero-copy byte handling |
| `serde_json` | 1 | Parse resize messages from browser |

## Configuration

```
rust-webtty [OPTIONS]

Options:
  --port <PORT>          Listen port (default: 8080)
  --password <SECRET>    Required. Auth token for WebSocket connections
  --shell <PATH>         Shell to spawn (default: $SHELL or $COMSPEC)
  --scrollback <BYTES>   Scrollback buffer size (default: 10240)
```

Missing `--password` → binary exits immediately with a clear error message.

## Error Handling

| Scenario | Behavior |
|----------|----------|
| No `--password` flag | Exit 1 with error message before binding port |
| Wrong WebSocket token | Close socket, no error detail (prevent enumeration) |
| PTY / shell exits | Broadcast message to all clients, session marked dead, reconnect shows notice |
| WebSocket disconnects | Unsubscribe from broadcast; PTY continues unaffected |
| PTY write error | Log warning; client likely disconnected |

## Frontend (embedded index.html)

- xterm.js loaded from CDN (or bundled for offline)
- `xterm-addon-fit` for terminal resize
- WebSocket connection with token in query string
- On open: attach to xterm, stream bytes directly (binary WebSocket frames)
- On resize: send JSON resize message
- Reconnect logic: exponential backoff, 5 retries

## Project Structure

```
rust-webtty/
├── Cargo.toml
├── src/
│   ├── main.rs          # CLI parsing, startup
│   ├── server.rs        # axum routes, WebSocket handler
│   ├── session.rs       # SharedSession, PTY lifecycle, broadcast
│   └── assets.rs        # rust-embed asset struct
├── assets/
│   └── index.html       # xterm.js terminal UI
└── docs/
    └── plans/
        └── 2026-02-25-rust-web-terminal-design.md
```
