use std::io::Write;
use std::sync::Arc;

use portable_pty::PtySize;

use axum::{
    extract::{Json, State, WebSocketUpgrade},
    extract::ws::{Message, WebSocket},
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Router,
};
use serde::Deserialize;
use tokio::sync::broadcast;

use crate::assets::Assets;
use crate::session::Session;

#[derive(Clone)]
pub struct AppState {
    pub session: Session,
    pub password: String,
    pub session_cookie: String,
}

#[derive(Deserialize)]
pub struct LoginRequest {
    password: String,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(serve_index))
        .route("/auth/login", post(auth_login))
        .route("/ws", get(ws_handler))
        .with_state(Arc::new(state))
}

async fn serve_index() -> impl IntoResponse {
    let html = Assets::get("index.html").unwrap();
    Html(std::str::from_utf8(html.data.as_ref()).unwrap().to_string())
}

async fn auth_login(
    State(state): State<Arc<AppState>>,
    Json(req): Json<LoginRequest>,
) -> Response {
    if check_token(&req.password, &state.password) {
        let set_cookie = format!(
            "webtty_session={}; HttpOnly; SameSite=Strict; Path=/",
            state.session_cookie
        );
        return (
            StatusCode::OK,
            [(header::SET_COOKIE, set_cookie)],
            "OK",
        )
            .into_response();
    }
    (StatusCode::UNAUTHORIZED, "Unauthorized").into_response()
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
) -> Response {
    let authorized = has_valid_session_cookie(&headers, &state.session_cookie);
    if !authorized {
        return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
    }
    ws.on_upgrade(move |socket| handle_socket(socket, state))
}

async fn handle_socket(mut socket: WebSocket, state: Arc<AppState>) {
    // Send scrollback to newly connected client, then subscribe to broadcast
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
                        if let Ok(msg) = serde_json::from_str::<serde_json::Value>(&text) {
                            if msg["type"] == "resize" {
                                let cols = msg["cols"].as_u64().unwrap_or(80) as u16;
                                let rows = msg["rows"].as_u64().unwrap_or(24) as u16;
                                let s = state.session.lock().unwrap();
                                let _ = s.pty_master.resize(PtySize {
                                    rows,
                                    cols,
                                    pixel_width: 0,
                                    pixel_height: 0,
                                });
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

/// Constant-time token comparison (XOR fold).
/// Note: length check leaks password length via timing — acceptable for a local dev tool.
pub fn check_token(token: &str, password: &str) -> bool {
    if token.len() != password.len() {
        return false;
    }
    token.as_bytes().iter().zip(password.as_bytes()).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0
}

fn has_valid_session_cookie(headers: &HeaderMap, expected: &str) -> bool {
    let raw_cookie = match headers.get(header::COOKIE).and_then(|value| value.to_str().ok()) {
        Some(value) => value,
        None => return false,
    };
    let Some(session) = cookie_value(raw_cookie, "webtty_session") else {
        return false;
    };
    check_token(session, expected)
}

fn cookie_value<'a>(cookie_header: &'a str, name: &str) -> Option<&'a str> {
    for part in cookie_header.split(';') {
        let trimmed = part.trim();
        let Some((key, value)) = trimmed.split_once('=') else {
            continue;
        };
        if key == name {
            return Some(value);
        }
    }
    None
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

    #[test]
    fn test_cookie_value_found() {
        let value = cookie_value("foo=1; webtty_session=abc123; bar=2", "webtty_session");
        assert_eq!(value, Some("abc123"));
    }

    #[test]
    fn test_cookie_value_missing() {
        let value = cookie_value("foo=1; bar=2", "webtty_session");
        assert_eq!(value, None);
    }
}
