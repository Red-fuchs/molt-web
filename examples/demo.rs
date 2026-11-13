//! Demo server on a mock moltd with neutral fixtures: `cargo run -p molt-web --example demo` (login: password demo-pass-1).
use molt_client::mock;
use serde_json::json;
use std::sync::Arc;

const PNG: &[u8] = include_bytes!("demo.png");

fn main() {
    let sum = { use sha2::{Digest, Sha256}; hex::encode(Sha256::digest(PNG)) };
    let id = "0123456789abcdef0123456789abcdef";
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
    let h: mock::Handler = Arc::new(move |name, a| Ok(match name {
        "status" => json!({"name":"Demo Republic","member":"seat","members":["bob","carol"],"chat_retention_days":7,"relays":["ws://a"]}),
        "read_state" => json!({"wiki_rev":1,"channels":[
            {"channel":{"kind":"group"},"count":4,"unread":2,"last_ts":now},{"channel":{"kind":"topic","name":"Ideen"},"count":1,"unread":0,"last_ts":now-50},
            {"channel":{"kind":"patch","id":4},"count":0,"unread":0,"last_ts":0,"state":"proposed"}],
          "applied":[
            {"id":"a1","from":"bob","ts":now-300,"kind":"user","body":"[Claude] Hallo!\nSchau: https://example.org/pfad?x=1, das reicht.\n```\n  /\\_/\\\n ( o.o )  <- nicht umbrechen, auch bei sehr langen Zeilen ---------------------------------\n  > ^ <\n```"},
            {"id":"a2","from":"carol","ts":now-200,"kind":"user","body":"<img src=x onerror=alert(1)> und \u{202e}evil","quote":"a1","reactions":{"👍":["bob"]}},
            {"id":id,"from":"bob","ts":now-100,"kind":"user","body":"[Bob] ein Bild","file":{"name":"demo.png","kind":"Image","size":PNG.len(),"checksum":sum}},
            {"id":"a4","from":"seat","ts":now-50,"kind":"user","body":"[Alice] @alice bitte schauen"},
            {"id":"a5","from":"bob","ts":now-40,"kind":"user","body":"Thema","channel":{"kind":"topic","name":"Ideen"}}]}),
        "list_proposals" => json!({"proposals":[{"id":4,"state":"proposed","by":"bob","payload":{"op":"wiki_patch","summary":"+1"},"approvals":1,"threshold":2,"votes":[{"member":"bob","vote":"approved"}]}]}),
        "read_actions" => json!({"actions":[{"kind":"vote","proposal":4}]}),
        "read_members" => json!({"members":[{"member":"bob","presence":0,"description":"Demo"},{"member":"carol","presence":1},{"member":"seat","presence":0}]}),
        "read_uploads" => json!({"uploads":[{"id":id,"name":"demo.png","kind":"Image","size":PNG.len(),"expires_ts":now+86400*5,"persistent":false,"local":"none","availability":"sharer-only","online":true,"available":true}]}),
        "download_file" => { std::fs::write(a["dest"].as_str().unwrap(), PNG).unwrap(); json!({"started":true}) }
        "share_file" => { eprintln!("MOCK share_file {a}"); json!({"id":"cccccccccccccccccccccccccccccccc"}) }
        "chat_send" => { eprintln!("MOCK chat_send {a}"); json!({"ok":true}) }
        _ => json!({"ok":true}),
    }));
    let m = mock::start("demo-token", h);
    let cache = std::env::temp_dir().join("molt-web-demo-cache");
    let listen = std::env::var("DEMO_LISTEN").unwrap_or_else(|_| "127.0.0.1:8481".into());
    let cfg = molt_web::config::Config {
        url: Some(m.url.clone()), token: Some("demo-token".into()), listen,
        users: vec![("Alice".into(), molt_web::auth::hash_password("demo-pass-1", 1000))],
        cache, poll_ms: 1000, max_file: 1 << 20, ..Default::default()
    };
    molt_web::serve(cfg, None).unwrap();
}
