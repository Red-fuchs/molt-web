use molt_client::text::clean;

/// Make a client-supplied file name safe as a single path component: no separators, no control/bidi chars,
/// no leading dots (so it can never be `.id` or hidden), at most 100 chars.
pub fn sanitize_name(raw: &str) -> String {
    let base = raw.rsplit(['/', '\\']).next().unwrap_or("");
    let s: String = clean(base).chars().filter(|c| !matches!(c, ':' | '"' | '<' | '>' | '|' | '?' | '*' | '\n')).collect();
    let s = s.trim().trim_start_matches('.').trim();
    let s: String = s.chars().take(100).collect();
    if s.trim().is_empty() { "file".into() } else { s.trim().to_string() }
}

#[cfg(test)]
mod t {
    use super::*;
    #[test]
    fn names() {
        assert_eq!(sanitize_name("../../etc/passwd"), "passwd");
        assert_eq!(sanitize_name("C:\\dir\\evil.exe"), "evil.exe");
        assert_eq!(sanitize_name(".hidden"), "hidden");
        assert_eq!(sanitize_name("..."), "file");
        assert_eq!(sanitize_name(".id"), "id");
        assert_eq!(sanitize_name(""), "file");
        assert_eq!(sanitize_name("a\u{202e}b\0c.png"), "abc.png");
        assert_eq!(sanitize_name("Bild 1 (final).png"), "Bild 1 (final).png");
        assert_eq!(sanitize_name(&"x".repeat(300)).chars().count(), 100);
        assert_eq!(sanitize_name("dir/"), "file");
    }
}
