use clap::Parser;

#[derive(Parser, Debug, Clone)]
#[command(name = "codewebway", about = "CodeWebway terminal over WebSocket")]
pub struct Config {
    /// Host/IP to bind (default: localhost only)
    #[arg(long, default_value = "127.0.0.1")]
    pub host: String,

    /// Port to listen on
    #[arg(long, default_value_t = 8080)]
    pub port: u16,

    /// Access token (auto-generated if not provided)
    #[arg(long)]
    pub password: Option<String>,

    /// Secondary login PIN (not printed on startup)
    #[arg(long)]
    pub pin: Option<String>,

    /// Shell to spawn (default: $SHELL on Unix, cmd.exe on Windows)
    #[arg(long)]
    pub shell: Option<String>,

    /// Working directory for spawned shell (default: current directory)
    #[arg(long)]
    pub cwd: Option<String>,

    /// Scrollback buffer size in bytes
    #[arg(long, default_value_t = 131072)]
    pub scrollback: usize,

    /// Create a public URL with zrok (requires `zrok` installed and enabled)
    #[arg(short = 'z', long)]
    pub zrok: bool,
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
        let cfg = Config::parse_from(["codewebway"]);
        assert_eq!(cfg.port, 8080);
    }

    #[test]
    fn test_default_host() {
        let cfg = Config::parse_from(["codewebway"]);
        assert_eq!(cfg.host, "127.0.0.1");
    }

    #[test]
    fn test_custom_host() {
        let cfg = Config::parse_from(["codewebway", "--host", "0.0.0.0"]);
        assert_eq!(cfg.host, "0.0.0.0");
    }

    #[test]
    fn test_custom_port() {
        let cfg = Config::parse_from(["codewebway", "--port", "9090"]);
        assert_eq!(cfg.port, 9090);
    }

    #[test]
    fn test_password_stored() {
        let cfg = Config::parse_from(["codewebway", "--password", "mysecret"]);
        assert_eq!(cfg.password, Some("mysecret".to_string()));
    }

    #[test]
    fn test_password_optional() {
        let cfg = Config::parse_from(["codewebway"]);
        assert!(cfg.password.is_none());
    }

    #[test]
    fn test_pin_optional() {
        let cfg = Config::parse_from(["codewebway"]);
        assert!(cfg.pin.is_none());
    }

    #[test]
    fn test_pin_stored() {
        let cfg = Config::parse_from(["codewebway", "--pin", "123456"]);
        assert_eq!(cfg.pin, Some("123456".to_string()));
    }

    #[test]
    fn test_shell_override() {
        let cfg = Config::parse_from(["codewebway", "--shell", "/bin/bash"]);
        assert_eq!(cfg.shell_path(), "/bin/bash");
    }

    #[test]
    fn test_cwd_stored() {
        let cfg = Config::parse_from(["codewebway", "--cwd", "/tmp"]);
        assert_eq!(cfg.cwd, Some("/tmp".to_string()));
    }

    #[test]
    fn test_shell_default_falls_back() {
        let cfg = Config::parse_from(["codewebway"]);
        assert!(!cfg.shell_path().is_empty());
    }

    #[test]
    fn test_zrok_flag_long() {
        let cfg = Config::parse_from(["codewebway", "--zrok"]);
        assert!(cfg.zrok);
    }

    #[test]
    fn test_zrok_flag_short() {
        let cfg = Config::parse_from(["codewebway", "-z"]);
        assert!(cfg.zrok);
    }
}
