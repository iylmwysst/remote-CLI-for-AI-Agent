# Design: `--terminal-only` Flag

**Date:** 2026-02-28
**Status:** Approved

## Problem

codewebway bundles a file explorer + editor alongside the terminal. Some deployments want a minimal, terminal-only surface with zero file-access exposure and maximum I/O focus.

## Goal

Add a `--terminal-only` runtime flag that:
- Drops the three `/api/fs/*` routes from the router (no file read/write/diff endpoints)
- Hides the Files panel in the browser UI (terminal expands to full width)
- Requires zero changes to the PTY/session/scrollback pipeline

## Non-Goals

- Compile-time feature flags (LTO already dead-strips unused code in release builds)
- Changes to scrollback, session timeouts, or zrok integration
- Compression or I/O pipeline changes

## Architecture

### config.rs
Add one field to `Config`:
```rust
/// Disable file explorer and editor (terminal-only mode)
#[arg(long)]
pub terminal_only: bool,
```

### server.rs — AppState
Add field:
```rust
pub terminal_only: bool,
```

### server.rs — router()
Move the three fs routes into a conditional block:
```rust
if !state.terminal_only {
    r = r
        .route("/api/fs/tree", get(fs_tree))
        .route("/api/fs/file", get(fs_file).put(save_file))
        .route("/api/fs/file/diff", patch(save_file_diff));
}
```

### server.rs — `/api/capabilities` (new)
Unauthenticated GET endpoint returning server feature flags:
```json
{ "terminal_only": false }
```
Frontend calls this once after login to adapt UI. No auth required (same as `/auth/session/status` pattern).

### assets/index.html
Two CSS rules:
```css
body.terminal-only #files { display: none; }
body.terminal-only #terms  { flex: 1; }
```

JS after login success:
```js
const caps = await api('/api/capabilities');
if (caps.terminal_only) document.body.classList.add('terminal-only');
```

## Files Changed

| File | Change |
|------|--------|
| `config.rs` | Add `--terminal-only` flag |
| `server.rs` | AppState field, conditional fs routes, new capabilities handler |
| `main.rs` | Pass `cfg.terminal_only` into AppState |
| `assets/index.html` | CSS + JS capability check |

## Version Bump

`0.3.24` → `0.3.25`
