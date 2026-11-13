use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;

pub const ITERS: u32 = 600_000;

pub fn rand_hex(n: usize) -> String {
    let mut b = vec![0u8; n];
    getrandom::fill(&mut b).expect("os rng");
    hex::encode(b)
}

pub fn hash_password(pw: &str, iters: u32) -> String {
    let salt = rand_hex(16);
    let mut out = [0u8; 32];
    pbkdf2_hmac::<Sha256>(pw.as_bytes(), salt.as_bytes(), iters, &mut out);
    format!("pbkdf2-sha256${iters}${salt}${}", hex::encode(out))
}

pub fn verify_password(pw: &str, stored: &str) -> bool {
    let p: Vec<&str> = stored.split('$').collect();
    let (Some(&"pbkdf2-sha256"), Some(it), Some(salt), Some(h)) = (p.first(), p.get(1).and_then(|s| s.parse::<u32>().ok()), p.get(2), p.get(3)) else { return false };
    let Ok(want) = hex::decode(h) else { return false };
    if it == 0 || it > 10_000_000 || want.len() != 32 { return false }
    let mut out = [0u8; 32];
    pbkdf2_hmac::<Sha256>(pw.as_bytes(), salt.as_bytes(), it, &mut out);
    out.ct_eq(&want[..]).into()
}

pub fn ct_eq(a: &str, b: &str) -> bool { a.len() == b.len() && a.as_bytes().ct_eq(b.as_bytes()).into() }

#[derive(Clone)]
pub struct Session { pub user: String, pub csrf: String, exp: Instant }

#[derive(Default)]
pub struct Sessions { m: Mutex<HashMap<String, Session>> }

const TTL: Duration = Duration::from_secs(7 * 86400);

impl Sessions {
    pub fn create(&self, user: &str) -> (String, Session) {
        let (tok, s) = (rand_hex(32), Session { user: user.into(), csrf: rand_hex(24), exp: Instant::now() + TTL });
        let mut m = self.m.lock().unwrap();
        let now = Instant::now();
        m.retain(|_, s| s.exp > now);
        if m.len() >= 64 && let Some(k) = m.iter().min_by_key(|(_, s)| s.exp).map(|(k, _)| k.clone()) { m.remove(&k); }
        m.insert(tok.clone(), s.clone());
        (tok, s)
    }
    pub fn get(&self, tok: &str) -> Option<Session> {
        let mut m = self.m.lock().unwrap();
        match m.get(tok) { Some(s) if s.exp > Instant::now() => Some(s.clone()), Some(_) => { m.remove(tok); None } None => None }
    }
    pub fn drop(&self, tok: &str) { self.m.lock().unwrap().remove(tok); }
}

/// Sliding-window attempt counter per key (login name, client IP). Attempts are counted BEFORE the expensive KDF runs.
#[derive(Default)]
pub struct Limiter { m: Mutex<HashMap<String, Vec<Instant>>> }

pub const WINDOW: Duration = Duration::from_secs(60);

impl Limiter {
    /// Register an attempt; false = over `max` within the window (attempt not allowed).
    pub fn attempt(&self, key: &str, max: usize) -> bool {
        let mut m = self.m.lock().unwrap();
        if m.len() > 4096 {
            m.retain(|_, v| { v.retain(|t| t.elapsed() < WINDOW); !v.is_empty() });
            if m.len() > 4096 { m.clear() }
        }
        let v = m.entry(key.to_string()).or_default();
        v.retain(|t| t.elapsed() < WINDOW);
        if v.len() >= max { return false }
        v.push(Instant::now());
        true
    }
    pub fn clear(&self, key: &str) { self.m.lock().unwrap().remove(key); }
}

#[cfg(test)]
mod t {
    use super::*;
    #[test]
    fn hash_roundtrip() {
        let h = hash_password("pw", 1000);
        assert!(h.starts_with("pbkdf2-sha256$1000$"));
        assert!(verify_password("pw", &h) && !verify_password("px", &h));
        assert!(!verify_password("pw", "garbage") && !verify_password("pw", "pbkdf2-sha256$0$a$00"));
    }
    #[test]
    fn sessions() {
        let s = Sessions::default();
        let (t, a) = s.create("u");
        assert_eq!(s.get(&t).unwrap().csrf, a.csrf);
        s.drop(&t);
        assert!(s.get(&t).is_none());
    }
    #[test]
    fn limiter_per_key() {
        let l = Limiter::default();
        for _ in 0..3 { assert!(l.attempt("u:a", 3)) }
        assert!(!l.attempt("u:a", 3));
        assert!(l.attempt("u:b", 3), "other keys unaffected");
        l.clear("u:a");
        assert!(l.attempt("u:a", 3));
    }
}
