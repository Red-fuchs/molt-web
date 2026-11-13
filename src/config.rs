use std::path::PathBuf;
use std::time::Duration;

#[derive(Clone)]
pub struct Config {
    pub url: Option<String>, pub token: Option<String>,
    pub listen: String,
    /// (login name, stored hash); the login name is also the sender tag of that user
    pub users: Vec<(String, String)>,
    pub read_only: bool, pub downloads: bool,
    pub cache: PathBuf, pub poll_ms: u64, pub secure: bool, pub max_file: u64, pub max_upload: u64,
    /// honour X-Forwarded-For (rightmost entry) for per-IP login limits; only behind a proxy you control
    pub trusted_proxy: bool,
    /// member pictures are served only from below this directory (moltd's data dir); None = never
    pub image_root: Option<PathBuf>,
    pub dl_timeout: Duration,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config").field("url", &self.url).field("token", &self.token.as_ref().map(|_| "<redacted>"))
            .field("listen", &self.listen).field("users", &self.users.iter().map(|u| &u.0).collect::<Vec<_>>())
            .field("read_only", &self.read_only).field("cache", &self.cache).finish_non_exhaustive()
    }
}

impl Default for Config {
    fn default() -> Self {
        Config { url: None, token: None, listen: "127.0.0.1:8480".into(), users: vec![], read_only: false, downloads: true,
            cache: PathBuf::from("molt-web-cache"), poll_ms: 2500, secure: false, max_file: 50 << 20, max_upload: 50 << 20,
            trusted_proxy: false, image_root: None, dl_timeout: Duration::from_secs(60) }
    }
}

pub const HELP: &str = "molt-web - Slack-like web UI for a MoltRepublic seat (talks to moltd over MCP)

  molt-web [--listen ADDR] [--url URL] [--token-file F] [--users-file F | --password-hash-file F]
           [--cache-dir D] [--read-only] [--secure-cookie] [--trusted-proxy] [--image-root D]
  molt-web hash-password        read a password from stdin, print the hash for the config

Config (in this order): flags, env, files
  MCP URL/token   --url/--token-file, MOLT_URL/MOLT_TOKEN, ~/.config/molt/url + token, default http://127.0.0.1:4040/mcp
  listen          --listen, MOLT_WEB_LISTEN, default 127.0.0.1:8480
  login           --users-file (lines `name:hash`), MOLT_WEB_USERS_FILE, ~/.config/molt/web-users
                  or a single user: --password-hash-file / MOLT_WEB_PASSWORD_HASH (login name = MOLT_ID, default `web`)
  sender tag      login name of the user; every message starts with [tag]
  MOLT_WEB_READONLY=1 / --read-only   refuse every write (send, upload, mark read) and file downloads
  MOLT_WEB_DOWNLOADS=0|1              file previews/downloads via download_file (default on unless read-only)
  MOLT_WEB_CACHE / --cache-dir        absolute dir the daemon can write to (downloads, uploads), mode 0700 (default ~/.cache/molt-web)
  MOLT_WEB_SECURE=1 / --secure-cookie Secure + __Host- session cookie (use behind https)
  MOLT_WEB_TRUSTED_PROXY=1 / --trusted-proxy   read the client IP from X-Forwarded-For (rightmost) for login limits
  MOLT_WEB_IMAGE_ROOT / --image-root  directory member pictures may be read from (moltd's data dir); unset = no member pictures
  MOLT_WEB_POLL_MS (default 2500), MOLT_WEB_MAX_FILE bytes (download, default 50 MB), MOLT_WEB_MAX_UPLOAD bytes (default 50 MB)";

fn flag(a: &[String], k: &str) -> Option<String> { a.iter().position(|x| x == k).and_then(|i| a.get(i + 1).cloned()) }
fn has(a: &[String], k: &str) -> bool { a.iter().any(|x| x == k) }
fn env(k: &str) -> Option<String> { std::env::var(k).ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty()) }
fn truthy(v: &str) -> bool { matches!(v.to_lowercase().as_str(), "1" | "true" | "yes" | "on") }
fn read(path: &str) -> Result<String, String> { std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}")) }

pub const MIN_ITERS: u32 = 100_000;

/// Sender tag of a single-user setup: MOLT_ID, else the neutral `web`.
pub fn default_tag() -> String { env("MOLT_ID").unwrap_or_else(|| "web".into()) }

pub fn hash_iters(h: &str) -> Option<u32> { h.split('$').nth(1)?.parse().ok() }

pub fn parse_users(txt: &str) -> Vec<(String, String)> {
    txt.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| l.split_once(':')).map(|(n, h)| (n.trim().to_string(), h.trim().to_string()))
        .filter(|(n, h)| !n.is_empty() && !h.is_empty() && n.chars().count() <= 32 && !n.contains(['[', ']']))
        .filter(|(n, h)| {
            let ok = hash_iters(h).is_some_and(|i| i >= MIN_ITERS);
            if !ok { eprintln!("molt-web: user {n}: hash rejected (needs pbkdf2-sha256 with >= {MIN_ITERS} iterations, see `molt-web hash-password`)") }
            ok
        }).collect()
}

impl Config {
    pub fn from_args(a: &[String]) -> Result<Config, String> {
        let home = env("HOME").unwrap_or_default();
        let token = match flag(a, "--token-file") { Some(f) => Some(read(&f)?.trim().to_string()), None => None };
        let mut users = vec![];
        let ufile = flag(a, "--users-file").or_else(|| env("MOLT_WEB_USERS_FILE"));
        let sfile = flag(a, "--password-hash-file");
        let single = |h: &str| parse_users(&format!("{}:{}", default_tag(), h.trim()));
        if let Some(f) = ufile { users = parse_users(&read(&f)?) }
        else if let Some(f) = sfile { users = single(&read(&f)?) }
        else if let Some(h) = env("MOLT_WEB_PASSWORD_HASH") { users = single(&h) }
        else if let Ok(t) = std::fs::read_to_string(format!("{home}/.config/molt/web-users")) { users = parse_users(&t) }
        if users.is_empty() { return Err("no usable login configured (--users-file, MOLT_WEB_PASSWORD_HASH or ~/.config/molt/web-users; hash: molt-web hash-password)".into()) }
        let read_only = has(a, "--read-only") || env("MOLT_WEB_READONLY").is_some_and(|v| truthy(&v));
        let downloads = if read_only { env("MOLT_WEB_DOWNLOADS").is_some_and(|v| truthy(&v)) } else { env("MOLT_WEB_DOWNLOADS").is_none_or(|v| truthy(&v)) };
        let d = Config::default();
        Ok(Config {
            url: flag(a, "--url"), token,
            listen: flag(a, "--listen").or_else(|| env("MOLT_WEB_LISTEN")).unwrap_or(d.listen),
            users, read_only, downloads,
            cache: flag(a, "--cache-dir").or_else(|| env("MOLT_WEB_CACHE")).map(PathBuf::from).unwrap_or_else(|| PathBuf::from(format!("{home}/.cache/molt-web"))),
            poll_ms: env("MOLT_WEB_POLL_MS").and_then(|v| v.parse().ok()).unwrap_or(2500).max(500),
            secure: has(a, "--secure-cookie") || env("MOLT_WEB_SECURE").is_some_and(|v| truthy(&v)),
            max_file: env("MOLT_WEB_MAX_FILE").and_then(|v| v.parse().ok()).unwrap_or(d.max_file),
            max_upload: env("MOLT_WEB_MAX_UPLOAD").and_then(|v| v.parse().ok()).unwrap_or(d.max_upload),
            trusted_proxy: has(a, "--trusted-proxy") || env("MOLT_WEB_TRUSTED_PROXY").is_some_and(|v| truthy(&v)),
            image_root: flag(a, "--image-root").or_else(|| env("MOLT_WEB_IMAGE_ROOT")).map(PathBuf::from),
            dl_timeout: d.dl_timeout,
        })
    }
}

#[cfg(test)]
mod t {
    use super::*;
    #[test]
    fn users_file() {
        let u = parse_users("# c\nalice:pbkdf2-sha256$600000$aa$bb\n\nbad line\nb[x]:h\n bob : pbkdf2-sha256$100000$a$b \nweak:pbkdf2-sha256$1000$a$b\n");
        assert_eq!(u, vec![("alice".into(), "pbkdf2-sha256$600000$aa$bb".into()), ("bob".into(), "pbkdf2-sha256$100000$a$b".into())]);
    }
    #[test]
    fn debug_has_no_secrets() {
        let c = Config { token: Some("TOPSECRET".into()), users: vec![("a".into(), "HASHVALUE".into())], ..Config::default() };
        let d = format!("{c:?}");
        assert!(!d.contains("TOPSECRET") && !d.contains("HASHVALUE"));
    }
}
