fn main() {
    let v = std::process::Command::new("git").args(["rev-parse", "--short", "HEAD"]).output().ok()
        .filter(|o| o.status.success()).and_then(|o| String::from_utf8(o.stdout).ok()).map(|s| s.trim().to_string()).unwrap_or_else(|| "unknown".into());
    println!("cargo:rustc-env=MOLT_WEB_VERSION={}-{v}", env!("CARGO_PKG_VERSION"));
    println!("cargo:rerun-if-changed=.git/HEAD");
}
