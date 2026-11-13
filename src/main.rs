use std::io::Read;

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    if a.iter().any(|x| x == "-h" || x == "--help") { println!("{}", molt_web::config::HELP); return }
    if a.first().map(String::as_str) == Some("hash-password") {
        let mut s = String::new();
        let _ = std::io::stdin().read_to_string(&mut s);
        let pw = s.trim_end_matches(['\n', '\r']);
        if pw.chars().count() < 8 { eprintln!("molt-web: password needs at least 8 characters"); std::process::exit(2) }
        println!("{}", molt_web::auth::hash_password(pw, molt_web::auth::ITERS));
        return;
    }
    let cfg = match molt_web::config::Config::from_args(&a) { Ok(c) => c, Err(e) => { eprintln!("molt-web: {e}"); std::process::exit(2) } };
    if let Err(e) = molt_web::serve(cfg, None) { eprintln!("molt-web: {e}"); std::process::exit(1) }
}
