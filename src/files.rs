use molt_client::mcp::Mcp;
use molt_client::model::FileMeta;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

/// Content type from magic bytes; only formats a browser may show inline.
pub fn magic(b: &[u8]) -> Option<&'static str> {
    if b.starts_with(&[0x89, b'P', b'N', b'G']) { Some("image/png") }
    else if b.starts_with(&[0xFF, 0xD8, 0xFF]) { Some("image/jpeg") }
    else if b.starts_with(b"GIF87a") || b.starts_with(b"GIF89a") { Some("image/gif") }
    else if b.len() > 12 && &b[..4] == b"RIFF" && &b[8..12] == b"WEBP" { Some("image/webp") }
    else { None }
}

#[derive(Debug, PartialEq)]
pub enum Check { Missing, Pending, Mismatch, Ok }

/// A regular file (never a symlink) of exactly the declared size whose sha256 matches (when declared).
pub fn verified(p: &Path, meta: &FileMeta) -> Check {
    let Ok(md) = std::fs::symlink_metadata(p) else { return Check::Missing };
    if !md.file_type().is_file() || md.len() != meta.size { return Check::Pending }
    let Ok(b) = std::fs::read(p) else { return Check::Pending };
    if b.len() as u64 != meta.size { return Check::Pending }
    if meta.checksum.len() == 64 && meta.checksum.bytes().all(|c| c.is_ascii_hexdigit()) && hex::encode(Sha256::digest(&b)) != meta.checksum { return Check::Mismatch }
    Check::Ok
}

fn done_locally(m: &Mcp, id: &str) -> bool {
    m.call("read_uploads", json!({})).ok().and_then(|v| v.get("uploads").and_then(|u| u.as_array()).and_then(|a| a.iter()
        .find(|r| r.get("id").and_then(|x| x.as_str()) == Some(id)).and_then(|r| r.get("local").and_then(|l| l.as_str()).map(|l| matches!(l, "downloaded" | "own")))))
        .unwrap_or(false)
}

/// Make sure the share is on disk in `cache` (daemon writes it, we verify size + sha256), return its path.
/// A checksum mismatch stays "pending" (the daemon may still be writing) until read_uploads reports the download done or the timeout hits.
pub fn ensure(m: &Mcp, cache: &Path, id: &str, meta: &FileMeta, max: u64, timeout: Duration) -> Result<PathBuf, String> {
    if meta.size > max { return Err(format!("file too large ({} > {max} bytes)", meta.size)) }
    let dest = cache.join(id);
    if verified(&dest, meta) == Check::Ok { return Ok(dest) }
    let _ = std::fs::remove_file(&dest);
    m.call("download_file", json!({"id": id, "dest": dest.to_string_lossy()}))?;
    let t0 = Instant::now();
    let mut last = Check::Missing;
    while t0.elapsed() < timeout {
        std::thread::sleep(Duration::from_millis(300));
        last = verified(&dest, meta);
        match last {
            Check::Ok => return Ok(dest),
            Check::Mismatch if done_locally(m, id) => break,
            _ => {}
        }
        if let Ok(v) = m.call("read_uploads", json!({})) {
            let row = v.get("uploads").and_then(|u| u.as_array()).and_then(|a| a.iter().find(|r| r.get("id").and_then(|x| x.as_str()) == Some(id)));
            if let Some(e) = row.and_then(|r| r.get("error")).and_then(|e| e.as_str()).filter(|e| !e.is_empty()) { let _ = std::fs::remove_file(&dest); return Err(molt_client::text::one(e)) }
        }
    }
    let _ = std::fs::remove_file(&dest);
    Err(if last == Check::Mismatch { "checksum does not match".into() } else { "timeout while loading".into() })
}

/// Delete cache files older than the chat retention. Downloaded shares: flat `<id>` files. Uploaded shares:
/// `uploads/<random>/` (file + `.id` with the share id); kept while the share is persistent, since moltd serves the bytes from here.
/// `now` is a parameter for tests. Returns the number of removed entries.
pub fn cleanup(cache: &Path, retention: Duration, persistent: &HashSet<String>, now: SystemTime) -> usize {
    let age = |p: &Path| std::fs::symlink_metadata(p).and_then(|m| m.modified()).ok().and_then(|t| now.duration_since(t).ok());
    let mut n = 0;
    if let Ok(rd) = std::fs::read_dir(cache) {
        for e in rd.flatten() {
            let p = e.path();
            let name = e.file_name().to_string_lossy().to_string();
            let is_dl = name.len() == 32 && name.bytes().all(|c| c.is_ascii_hexdigit());
            if is_dl && !persistent.contains(&name) && age(&p).is_some_and(|a| a > retention) && std::fs::remove_file(&p).is_ok() { n += 1 }
        }
    }
    if let Ok(rd) = std::fs::read_dir(cache.join("uploads")) {
        for e in rd.flatten() {
            let d = e.path();
            if !d.is_dir() { continue }
            let id = std::fs::read_to_string(d.join(".id")).ok().map(|s| s.trim().to_string());
            let a = age(&d).unwrap_or_default();
            let limit = if id.is_some() { retention + Duration::from_secs(86400) } else { Duration::from_secs(3600) };
            if a > limit && !id.as_ref().is_some_and(|i| persistent.contains(i)) && std::fs::remove_dir_all(&d).is_ok() { n += 1 }
        }
    }
    n
}

#[cfg(test)]
mod t {
    use super::*;
    use std::os::unix::fs::symlink;
    fn tmp(n: &str) -> PathBuf { let p = std::env::temp_dir().join(format!("molt-web-{n}{}", crate::auth::rand_hex(4))); std::fs::create_dir_all(&p).unwrap(); p }
    #[test]
    fn sniff() {
        assert_eq!(magic(b"\x89PNG\r\n"), Some("image/png"));
        assert_eq!(magic(b"<svg onload=alert(1)>"), None);
        assert_eq!(magic(b"RIFF\0\0\0\0WEBPVP8 "), Some("image/webp"));
    }
    #[test]
    fn verified_rules() {
        let d = tmp("v");
        let meta = FileMeta { name: "a".into(), kind: "".into(), size: 3, checksum: hex::encode(Sha256::digest(b"abc")) };
        assert_eq!(verified(&d.join("none"), &meta), Check::Missing);
        std::fs::write(d.join("ok"), b"abc").unwrap();
        assert_eq!(verified(&d.join("ok"), &meta), Check::Ok);
        std::fs::write(d.join("short"), b"ab").unwrap();
        assert_eq!(verified(&d.join("short"), &meta), Check::Pending);
        std::fs::write(d.join("bad"), b"abd").unwrap();
        assert_eq!(verified(&d.join("bad"), &meta), Check::Mismatch);
        symlink(d.join("ok"), d.join("link")).unwrap();
        assert_eq!(verified(&d.join("link"), &meta), Check::Pending, "symlinks are never followed");
        std::fs::create_dir(d.join("dir")).unwrap();
        assert_eq!(verified(&d.join("dir"), &meta), Check::Pending);
    }
    #[test]
    fn cleanup_rules() {
        let c = tmp("cl");
        let week = Duration::from_secs(7 * 86400);
        let (old, keep) = ("a".repeat(32), "b".repeat(32));
        std::fs::write(c.join(&old), b"x").unwrap();
        std::fs::write(c.join(&keep), b"x").unwrap();
        std::fs::write(c.join("notes.txt"), b"x").unwrap();
        for (dir, id) in [("u1", Some("1".repeat(32))), ("u2", Some("2".repeat(32))), ("u3", None)] {
            let d = c.join("uploads").join(dir);
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(d.join("f.bin"), b"x").unwrap();
            if let Some(i) = id { std::fs::write(d.join(".id"), i).unwrap() }
        }
        let pers: HashSet<String> = [keep.clone(), "2".repeat(32)].into();
        // fresh: nothing goes, except nothing is old yet
        assert_eq!(cleanup(&c, week, &pers, SystemTime::now()), 0);
        // 2 hours later: only the upload without a share id (failed share) goes
        let n = cleanup(&c, week, &pers, SystemTime::now() + Duration::from_secs(7200));
        assert_eq!(n, 1);
        assert!(!c.join("uploads/u3").exists() && c.join("uploads/u1").exists());
        // after retention + 1 day: unpersisted download and upload go, persisted ones and foreign files stay
        let late = SystemTime::now() + week + Duration::from_secs(2 * 86400);
        assert_eq!(cleanup(&c, week, &pers, late), 2);
        assert!(!c.join(&old).exists() && c.join(&keep).exists() && c.join("notes.txt").exists());
        assert!(!c.join("uploads/u1").exists() && c.join("uploads/u2/f.bin").exists());
    }
}
