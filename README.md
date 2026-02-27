```text
      ____          _     __        __   _
     / ___|___   __| | ___\ \      / /__| |____      ____ _ _   _
    | |   / _ \ / _` |/ _ \\ \ /\ / / _ \ '_ \ \ /\ / / _` | | | |
    | |__| (_) | (_| |  __/ \ V  V /  __/ |_) \ V  V / (_| | |_| |
     \____\___/ \__,_|\___|  \_/\_/ \___|_.__/ \_/\_/ \__,_|\__, |
                                                            |___/
          [ A seamless, single-binary web terminal and file editor. ]
```

CodeWebway is a lightweight Rust tool for secure browser-based terminal access and quick file editing. It is designed for personal workflows, headless machines, and remote AI-agent sessions.

## How It Works

```text
Browser <-> WebSocket <-> CodeWebway <-> Host shell (PTY)
```

- One local process hosts both backend and web UI.
- Terminal tabs are server-side PTY sessions.
- Browser clients reconnect and resume session state.

## Why Use This?

### Convenience

- **Remote CLI from any device**: run builds, scripts, and diagnostics from browser.
- **Headless-friendly**: no desktop, VNC, or extra daemon required.
- **Built-in file workflow**: browse, preview, and edit project files in the same UI.
- **zrok-ready**: use `-z` to publish a URL without manual reverse-proxy setup.
- **Single binary**: fast startup, minimal dependencies, low resource use.

### Security

- **2-step login**: token + PIN.
- **PIN policy**: PIN must be numeric and at least 6 digits.
- **Rate limit + lockout**: blocks repeated login failures.
- **Session expiry + logout controls**: supports current-session and revoke-all behavior.
- **Temporary links**: create time-limited share URLs with scope (`read-only` / `interactive`) and one-time use.
- **Connection cap**: concurrent WebSocket sessions are limited (`--max-connections`).
- **Origin validation on WebSocket**: mitigates cross-site WS hijacking.
- **Safe default bind**: `127.0.0.1` by default; public exposure is opt-in.

## Quick Start

### Install (macOS / Linux)

```bash
curl -fsSL https://raw.githubusercontent.com/iylmwysst/CodeWebway/main/install.sh | sh
```

### Run

```bash
codewebway -z
```

Startup prints token, bind address, and open URL. Open the URL in your browser and login with token + PIN.
Use startup flags to issue temporary links (`/t/<token>`) without sharing your primary credentials.

## CLI Usage

```text
codewebway [OPTIONS]

Options:
  --host <HOST>          Listen host [default: 127.0.0.1]
  --port <PORT>          Listen port [default: 8080]
  --password <PASSWORD>  Fixed token (min 16 chars; auto-generated if omitted)
  --pin <PIN>            Secondary login PIN (numeric, at least 6 digits)
  --shell <PATH>         Shell executable [default: $SHELL]
  --cwd <PATH>           Working directory [default: current directory]
  --scrollback <BYTES>   Scrollback size [default: 131072]
  --max-connections <N>  Max concurrent WebSocket connections [default: 8]
  --temp-link            Generate one temporary link at startup
  --temp-link-ttl-minutes <N>
                         Temporary link TTL (5, 15, 60) [default: 15]
  --temp-link-scope <S>  Temporary link scope: read-only|interactive [default: read-only]
  --temp-link-max-uses <N>
                         Temporary link max uses [default: 1]
  -z, --zrok             Start zrok public share (zrok required)
  --public-timeout-minutes <N>
                         Auto-disable public zrok share after N minutes
  --public-no-expiry     Keep public zrok share active until lockout + shutdown
  -h, --help             Print help
```

## Public Access Options

- **zrok (recommended)**

```bash
codewebway -z
```

Requires `zrok` to be installed and enabled on the host:

```bash
zrok enable <your_enable_token>
```

- **Tailscale / ngrok** (manual exposure)

```bash
ngrok http 8080
# or run on tailscale and open http://<tailscale-ip>:8080
```

## Build From Source

Requirements: [Rust](https://rustup.rs) 1.75+

```bash
git clone https://github.com/iylmwysst/CodeWebway
cd CodeWebway
cargo build --release
./target/release/codewebway
```

## Tech Stack

| Component | Tooling |
|---|---|
| HTTP + WebSocket | `axum` |
| PTY | `portable-pty` |
| Runtime | `tokio` |
| Embedded assets | `rust-embed` |
| CLI | `clap` |
| Terminal UI | `xterm.js` |

## License

GNU GPL v3.0. See [LICENSE](LICENSE).
