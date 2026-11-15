//! Votes, proposals, withdraw and topics against the stateful in-process republic (mock::sim); the live moltd is never contacted.
use molt_client::mock::{self, sim::Sim, Mock};
use molt_web::config::Config;
use serde_json::{json, Value};
use std::io::{BufRead, BufReader};
use std::sync::mpsc;

const TOKEN: &str = "TEST-TOKEN-0123456789";
const PW: &str = "correct horse";
struct Env { mock: Mock, base: String, sim: std::sync::Arc<std::sync::Mutex<Sim>> }
struct Sess { cookie: String, csrf: String }

fn boot(read_only: bool, admins: &[&str]) -> Env {
    let mut sim = Sim::new("seat-a");
    let (h, simh) = sim.into_handler(None);
    let m = mock::start(TOKEN, h);
    let cache = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("w{}", molt_web::auth::rand_hex(6)));
    let cfg = Config { url: Some(m.url.clone()), token: Some(TOKEN.into()), listen: "127.0.0.1:0".into(),
        users: vec![("alice".into(), molt_web::auth::hash_password(PW, 1000))], read_only, cache, poll_ms: 300, admins: molt_web::config::parse_admins(&admins.join(",")), ..Config::default() };
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || molt_web::serve(cfg, Some(tx)).unwrap());
    let addr = rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
    Env { mock: m, base: format!("http://{addr}"), sim: simh }
}

fn call(method: &str, url: &str, s: Option<&Sess>, csrf: bool, origin: Option<&str>, body: Option<Value>) -> (u16, Value) {
    let mut r = ureq::request(method, url);
    if let Some(s) = s { r = r.set("Cookie", &s.cookie); if csrf { r = r.set("X-CSRF-Token", &s.csrf) } }
    if let Some(o) = origin { r = r.set("Origin", o) }
    let res = match body { Some(b) => r.set("Content-Type", "application/json").send_string(&b.to_string()), None => r.call() };
    let resp = match res { Ok(r) => r, Err(ureq::Error::Status(_, r)) => r, Err(e) => panic!("{e}") };
    let code = resp.status();
    (code, serde_json::from_str(&resp.into_string().unwrap()).unwrap_or(Value::Null))
}
fn post(e: &Env, s: &Sess, path: &str, b: Value) -> (u16, Value) { call("POST", &format!("{}{path}", e.base), Some(s), true, None, Some(b)) }

fn login(e: &Env) -> Sess {
    let r = ureq::post(&format!("{}/api/login", e.base)).set("Content-Type", "application/json").send_string(&json!({"password":PW}).to_string()).unwrap();
    let ck = r.header("set-cookie").unwrap().split(';').next().unwrap().to_string();
    let j: Value = serde_json::from_str(&r.into_string().unwrap()).unwrap();
    assert!(j["kinds"].as_array().unwrap().len() >= 9);
    Sess { cookie: ck, csrf: j["csrf"].as_str().unwrap().into() }
}
fn state(e: &Env, s: &Sess, pred: impl Fn(&Value) -> bool) -> Value {
    let resp = ureq::get(&format!("{}/api/events", e.base)).set("Cookie", &s.cookie).call().unwrap();
    for l in BufReader::new(resp.into_reader()).lines() {
        if let Some(d) = l.unwrap().strip_prefix("data:") {
            let v: Value = serde_json::from_str(d.trim()).unwrap();
            if v.get("loading").is_none() && pred(&v) { return v }
        }
    }
    panic!("state never matched")
}

fn get(e: &Env, s: Option<&Sess>, path: &str) -> (u16, Value) { call("GET", &format!("{}{path}", e.base), s, false, None, None) }

#[test]
fn log_is_admin_only_and_filtered() {
    let e = boot(false, &[]);
    e.sim.lock().unwrap().log = vec!["sent proposal 4 to 10.1.2.3:4040".into(), "chat noise".into(), "refused vote 5".into()];
    let s = login(&e);
    assert_eq!(get(&e, None, "/api/diag/log").0, 401);
    let (c, j) = get(&e, Some(&s), "/api/diag/log");
    assert_eq!(c, 403, "{j}");
    assert!(e.mock.called("read_log").is_empty());
    assert_eq!(post(&e, &s, "/api/diag/test_wake", json!({"confirm":true})).0, 403);
    assert!(e.mock.called("test_wake").is_empty());
    assert_eq!(get(&e, Some(&s), "/api/me").1["admin"], false);
    let (_, j) = get(&e, Some(&s), "/api/diag/chain");
    assert!(j["text"].as_str().unwrap().contains("abc"));
}

#[test]
fn admin_reads_log_and_runs_wake() {
    let e = boot(false, &["ALICE"]);
    e.sim.lock().unwrap().log = vec!["sent proposal 4 to 10.1.2.3:4040".into(), "chat noise".into(), "refused vote 5".into()];
    let s = login(&e);
    assert_eq!(get(&e, Some(&s), "/api/me").1["admin"], true);
    let (c, j) = get(&e, Some(&s), "/api/diag/log");
    assert_eq!(c, 200);
    let l = j["lines"].as_array().unwrap();
    assert_eq!(l.len(), 2);
    assert!(l[0].as_str().unwrap().contains("10.1.2.3"));
    assert_eq!(get(&e, Some(&s), "/api/diag/log?q=vote").1["lines"].as_array().unwrap().len(), 1);
    assert_eq!(post(&e, &s, "/api/diag/test_wake", json!({})).0, 400); // confirm needed
    let (c, j) = post(&e, &s, "/api/diag/test_wake", json!({"confirm":true}));
    assert!(c == 200 && j["ok"] == true, "{j}");
    assert_eq!(e.mock.called("test_wake").len(), 1);
    assert!(get(&e, Some(&s), "/api/diag/wake_skill").1["text"].as_str().unwrap().contains("wake"));
    assert!(get(&e, Some(&s), "/api/diag/mirror").1["text"].as_str().unwrap().contains("in-sync"));
}

#[test]
fn clear_notice_csrf_confirm_validation() {
    let e = boot(false, &[]);
    e.sim.lock().unwrap().notices = vec!["n1".into(), "n2".into()];
    let s = login(&e);
    let url = format!("{}/api/diag/clear_notice", e.base);
    assert_eq!(call("POST", &url, Some(&s), false, None, Some(json!({"id":"n1","confirm":true}))).0, 403, "csrf");
    assert_eq!(call("POST", &url, Some(&s), true, Some("http://evil.example"), Some(json!({"id":"n1","confirm":true}))).0, 403, "origin");
    assert_eq!(post(&e, &s, "/api/diag/clear_notice", json!({"id":"n1"})).0, 400);
    assert_eq!(post(&e, &s, "/api/diag/clear_notice", json!({"id":5,"confirm":true})).0, 400);
    assert!(e.mock.called("clear_notice").is_empty());
    assert_eq!(post(&e, &s, "/api/diag/clear_notice", json!({"id":"n1","confirm":true})).0, 200);
    assert_eq!(e.sim.lock().unwrap().notices, ["n2"]);
    assert_eq!(post(&e, &s, "/api/diag/clear_notice", json!({"confirm":true})).0, 200);
    assert!(e.sim.lock().unwrap().notices.is_empty());
}

#[test]
fn read_only_blocks_writes_and_upload_resolve() {
    let e = boot(true, &["alice"]);
    let s = login(&e);
    assert_eq!(post(&e, &s, "/api/diag/clear_notice", json!({"confirm":true})).0, 403);
    assert_eq!(post(&e, &s, "/api/diag/test_wake", json!({"confirm":true})).0, 403);
    assert!(e.mock.called("clear_notice").is_empty() && e.mock.called("test_wake").is_empty());
    assert_eq!(get(&e, Some(&s), "/api/diag/upload/zz").0, 400);
    let (c, j) = get(&e, Some(&s), &format!("/api/diag/upload/{}", "a".repeat(32)));
    assert!(c == 200 && j["text"].as_str().unwrap().contains("available"), "{j}");
}

#[test]
fn upload_vote_reaches_snapshot_and_vote_endpoint_works() {
    let e = boot(false, &[]);
    {
        let mut sim = e.sim.lock().unwrap();
        let id = sim.say_file("bob", "a.txt", "file", b"hi", None);
        let u = sim.uploads.iter_mut().find(|u| u["id"] == id.as_str()).unwrap();
        u["vote"] = json!({"op":"persist","proposal":4,"mine_open":true});
    }
    let s = login(&e);
    let st = state(&e, &s, |v| v["msgs"].as_array().is_some_and(|m| m.iter().any(|x| x["file"]["upload"]["vote"]["proposal"] == 4)));
    let m = st["msgs"].as_array().unwrap().iter().find(|x| x["file"]["upload"]["vote"].is_object()).unwrap();
    assert_eq!(m["file"]["upload"]["vote"], json!({"op":"persist","proposal":4,"mine_open":true}));
    let (c, j) = post(&e, &s, "/api/vote", json!({"id":4,"approve":true,"confirm":true}));
    assert!(c == 200 && j["ok"] == true, "{j}");
}
