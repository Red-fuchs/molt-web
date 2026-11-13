//! End to end against an in-process MCP mock; the live moltd is never contacted.
use molt_client::mock::{self, Mock};
use molt_web::config::Config;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::{BufRead, BufReader};
use std::sync::{mpsc, Arc};

const TOKEN: &str = "TEST-TOKEN-0123456789";
const PW: &str = "correct horse";
const MID: &str = "0123456789abcdef0123456789abcdef";
const MID2: &str = "fedcba9876543210fedcba9876543210";
const MID3: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const MID4: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const PNG: &[u8] = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDRxxxxxxxxxxxx";

struct Env { mock: Mock, base: String, cache: std::path::PathBuf }

fn boot(read_only: bool) -> Env { boot_with(read_only, |_| {}) }

fn boot_with(read_only: bool, tweak: impl FnOnce(&mut Config)) -> Env {
    let cache = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("c{}", molt_web::auth::rand_hex(6)));
    let sum = hex::encode(Sha256::digest(PNG));
    let h: mock::Handler = Arc::new(move |name, a| Ok(match name {
        "status" => json!({"name":"Demo Republic","member":"alice-seat","members":["bob","alice-seat"],"chat_retention_days":7,"relays":["ws://a"]}),
        "read_state" => json!({"wiki_rev":1,"channels":[
            {"channel":{"kind":"group"},"count":3,"unread":2,"last_ts":30},{"channel":{"kind":"topic","name":"Ideen"},"count":1,"unread":0,"last_ts":20}],
          "applied":[
            {"id":MID3,"from":"bob","ts":10,"kind":"user","body":"[Claude] hallo ```\n  /\\_/\\\n ( o.o )\n```"},
            {"id":MID,"from":"bob","ts":20,"kind":"user","body":"bild","quote":MID3,"file":{"name":"a.png","kind":"Image","size":PNG.len(),"checksum":sum,"key_b64":"SECRET-KEY"}},
            {"id":MID2,"from":"bob","ts":30,"kind":"user","body":"evil","file":{"name":"x.png","kind":"Image","size":PNG.len(),"checksum":"00".repeat(32)}}]}),
        "list_proposals" => json!({"proposals":[{"id":4,"state":"proposed","by":"bob","payload":{"op":"wiki_patch","summary":"+1"},"approvals":1,"threshold":2,"votes":[]}]}),
        "read_actions" => json!({"actions":[{"kind":"vote","proposal":4}]}),
        "read_members" => json!({"members":[{"member":"bob","image":"","presence":0},{"member":"alice-seat","presence":2}]}),
        "read_uploads" => json!({"uploads":[{"id":MID,"name":"a.png","kind":"Image","size":PNG.len(),"expires_ts":4102444800i64,"persistent":false,"local":"none","availability":"sharer-only","online":true,"available":true}]}),
        "download_file" => {
            let id = a["id"].as_str().unwrap();
            let dest = a["dest"].as_str().unwrap();
            assert!(dest.starts_with('/'), "dest must be absolute");
            std::fs::write(dest, if id == MID { PNG.to_vec() } else { vec![b'z'; PNG.len()] }).unwrap();
            json!({"started":true})
        }
        "chat_send" | "mark_channel_read" => json!({"ok":true}),
        "share_file" => { assert!(a["path"].as_str().unwrap().starts_with('/')); json!({"id": MID4}) }
        _ => return Err(format!("unexpected tool {name}")),
    }));
    let m = mock::start(TOKEN, h);
    let mut cfg = Config {
        url: Some(m.url.clone()), token: Some(TOKEN.into()), listen: "127.0.0.1:0".into(),
        users: vec![("alice".into(), molt_web::auth::hash_password(PW, 1000))],
        read_only, downloads: !read_only, cache: cache.clone(), poll_ms: 500, max_file: 1 << 20, max_upload: 1 << 20,
        dl_timeout: std::time::Duration::from_secs(3), ..Config::default()
    };
    tweak(&mut cfg);
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || { molt_web::serve(cfg, Some(tx)).unwrap() });
    let addr = rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
    Env { mock: m, base: format!("http://{addr}"), cache }
}

struct R { code: u16, body: Vec<u8>, ct: String, hdr: Vec<(String, String)> }
impl R {
    fn json(&self) -> Value { serde_json::from_slice(&self.body).unwrap_or(Value::Null) }
    fn h(&self, k: &str) -> String { self.hdr.iter().find(|(n, _)| n.eq_ignore_ascii_case(k)).map(|x| x.1.clone()).unwrap_or_default() }
}
fn req(method: &str, url: &str, cookie: Option<&str>, csrf: Option<&str>, origin: Option<&str>, body: Option<Value>) -> R {
    req_x(method, url, cookie, csrf, origin, body.map(|b| (b.to_string().into_bytes(), "application/json")), &[])
}
fn req_x(method: &str, url: &str, cookie: Option<&str>, csrf: Option<&str>, origin: Option<&str>, body: Option<(Vec<u8>, &str)>, extra: &[(&str, &str)]) -> R {
    let mut r = ureq::request(method, url);
    for (k, v) in extra { r = r.set(k, v) }
    if let Some(c) = cookie { r = r.set("Cookie", c) }
    if let Some(c) = csrf { r = r.set("X-CSRF-Token", c) }
    if let Some(o) = origin { r = r.set("Origin", o) }
    let res = match body { Some((b, ct)) => r.set("Content-Type", ct).send_bytes(&b), None => r.call() };
    let resp = match res { Ok(r) => r, Err(ureq::Error::Status(_, r)) => r, Err(e) => panic!("{e}") };
    let (code, ct) = (resp.status(), resp.content_type().to_string());
    let hdr = resp.headers_names().into_iter().filter_map(|n| resp.header(&n).map(|v| (n.clone(), v.to_string()))).collect();
    let mut body = vec![];
    std::io::Read::read_to_end(&mut resp.into_reader(), &mut body).unwrap();
    R { code, body, ct, hdr }
}

struct Sess { cookie: String, csrf: String }
fn login(e: &Env) -> Sess {
    let r = req("POST", &format!("{}/api/login", e.base), None, None, None, Some(json!({"password":PW})));
    assert_eq!(r.code, 200, "{}", String::from_utf8_lossy(&r.body));
    let sc = r.h("set-cookie");
    assert!(sc.contains("HttpOnly") && sc.contains("SameSite=Strict") && sc.contains("Path=/"), "{sc}");
    Sess { cookie: sc.split(';').next().unwrap().to_string(), csrf: r.json()["csrf"].as_str().unwrap().to_string() }
}
fn first_state(e: &Env, s: &Sess) -> Value {
    let resp = ureq::get(&format!("{}/api/events", e.base)).set("Cookie", &s.cookie).call().unwrap();
    assert!(resp.content_type().starts_with("text/event-stream"));
    for l in BufReader::new(resp.into_reader()).lines() {
        let l = l.unwrap();
        if let Some(d) = l.strip_prefix("data:") {
            let v: Value = serde_json::from_str(d.trim()).unwrap();
            if v.get("loading").is_none() { return v }
        }
    }
    panic!("no state")
}

#[test]
fn auth_state_and_secrets() {
    let e = boot(false);
    assert_eq!(req("GET", &format!("{}/api/me", e.base), None, None, None, None).code, 401);
    assert_eq!(req("GET", &format!("{}/api/events", e.base), None, None, None, None).code, 401);
    assert_eq!(req("POST", &format!("{}/api/login", e.base), None, None, None, Some(json!({"password":"nope"}))).code, 401);
    let s = login(&e);
    let me = req("GET", &format!("{}/api/me", e.base), Some(&s.cookie), None, None, None).json();
    assert_eq!((me["user"].as_str(), me["tag"].as_str()), (Some("alice"), Some("alice")));
    let st = first_state(&e, &s);
    assert_eq!(st["name"], "Demo Republic");
    assert_eq!(st["todo"], 1);
    assert_eq!(st["props"][0]["chan"], "p:4");
    let m = st["msgs"].as_array().unwrap().iter().find(|m| m["id"] == MID3).unwrap();
    assert_eq!((m["tag"].as_str(), m["body"].as_str().unwrap().starts_with("hallo ```")), (Some("Claude"), true));
    let f = st["msgs"].as_array().unwrap().iter().find(|m| m["id"] == MID).unwrap();
    assert_eq!((f["file"]["image"].clone(), f["file"]["upload"]["persistent"].clone()), (json!(true), json!(false)));
    // the MCP token and the daemon's file key never reach the browser
    let mut all = serde_json::to_string(&st).unwrap();
    for p in ["/", "/app.js", "/style.css"] { all += &String::from_utf8_lossy(&req("GET", &format!("{}{p}", e.base), None, None, None, None).body) }
    all += &serde_json::to_string(&me).unwrap();
    assert!(!all.contains(TOKEN) && !all.contains("SECRET-KEY") && !all.contains(PW));
    let idx = req("GET", &format!("{}/", e.base), None, None, None, None);
    assert!(idx.h("content-security-policy").contains("script-src 'self'") && idx.h("x-content-type-options") == "nosniff");
    assert!(!String::from_utf8_lossy(&idx.body).contains("<script>"), "no inline scripts (CSP)");
}

#[test]
fn send_flow_csrf_and_tag() {
    let e = boot(false);
    let s = login(&e);
    let _ = first_state(&e, &s);
    let url = format!("{}/api/send", e.base);
    let body = json!({"body":"hello\nworld","channel":{"kind":"topic","name":"Ideen"},"quote":MID});
    assert_eq!(req("POST", &url, Some(&s.cookie), None, None, Some(body.clone())).code, 403, "csrf missing");
    assert_eq!(req("POST", &url, Some(&s.cookie), Some("wrong"), None, Some(body.clone())).code, 403);
    assert_eq!(req("POST", &url, Some(&s.cookie), Some(&s.csrf), Some("http://evil.example"), Some(body.clone())).code, 403, "foreign origin");
    assert_eq!(req("POST", &url, None, Some(&s.csrf), None, Some(body.clone())).code, 401);
    assert!(e.mock.called("chat_send").is_empty());
    let host = e.base.trim_start_matches("http://");
    let r = req("POST", &url, Some(&s.cookie), Some(&s.csrf), Some(&format!("http://{host}")), Some(body));
    assert_eq!(r.code, 200, "{}", String::from_utf8_lossy(&r.body));
    let c = e.mock.called("chat_send");
    assert_eq!(c.len(), 1);
    assert_eq!(c[0]["body"], "[alice] hello\nworld");
    assert_eq!(c[0]["channel"], json!({"kind":"topic","name":"Ideen"}));
    assert_eq!(c[0]["quote"], MID);
    // group channel = no channel arg; bad inputs rejected without reaching the daemon
    assert_eq!(req("POST", &url, Some(&s.cookie), Some(&s.csrf), None, Some(json!({"body":"x","channel":{"kind":"group"}}))).code, 200);
    assert!(e.mock.called("chat_send")[1].get("channel").is_none());
    for bad in [json!({"body":"  "}), json!({"body":"x","quote":"not-a-known-id"}), json!({"body":"x","channel":{"kind":"topic","name":""}}), json!({"body":"x","channel":{"kind":"nope"}})] {
        assert_eq!(req("POST", &url, Some(&s.cookie), Some(&s.csrf), None, Some(bad)).code, 400);
    }
    assert_eq!(e.mock.called("chat_send").len(), 2);
    let r = req("POST", &format!("{}/api/mark_read", e.base), Some(&s.cookie), Some(&s.csrf), None, Some(json!({"channel":{"kind":"patch","id":4}})));
    assert_eq!(r.code, 200);
    assert_eq!(e.mock.called("mark_channel_read")[0]["channel"], json!({"kind":"patch","id":4}));
    assert!(e.mock.called("mark_read").is_empty(), "never broadcast read receipts");
}

#[test]
fn files_verified_and_sniffed() {
    let e = boot(false);
    let s = login(&e);
    let _ = first_state(&e, &s);
    let get = |id: &str, q: &str| req("GET", &format!("{}/api/file/{id}{q}", e.base), Some(&s.cookie), None, None, None);
    let r = get(MID, "");
    assert_eq!((r.code, r.ct.as_str(), r.body.as_slice()), (200, "image/png", PNG));
    assert!(r.h("content-security-policy").contains("sandbox"));
    assert_eq!(get(MID, "").code, 200);
    let dl = e.mock.called("download_file");
    assert_eq!(dl.len(), 1, "second hit served from cache");
    assert!(dl[0]["dest"].as_str().unwrap().starts_with(e.cache.canonicalize().unwrap().to_str().unwrap()));
    let r = get(MID, "?dl=1");
    assert_eq!(r.ct, "application/octet-stream");
    assert!(r.h("content-disposition").starts_with("attachment"));
    assert_eq!(get(MID2, "").code, 502, "checksum mismatch is refused");
    assert_eq!(get("not-hex", "").code, 400);
    assert_eq!(get(&"b".repeat(32), "").code, 404, "only shares seen in chat");
    assert_eq!(req("GET", &format!("{}/api/file/{MID}", e.base), None, None, None, None).code, 401);
}

#[test]
fn read_only_blocks_writes() {
    let e = boot(true);
    let s = login(&e);
    let st = first_state(&e, &s);
    assert_eq!(st["msgs"].as_array().unwrap().len(), 3);
    assert_eq!(req("POST", &format!("{}/api/send", e.base), Some(&s.cookie), Some(&s.csrf), None, Some(json!({"body":"x"}))).code, 403);
    assert_eq!(req("POST", &format!("{}/api/mark_read", e.base), Some(&s.cookie), Some(&s.csrf), None, Some(json!({}))).code, 403);
    assert_eq!(req("GET", &format!("{}/api/file/{MID}", e.base), Some(&s.cookie), None, None, None).code, 403);
    let names: Vec<String> = e.mock.calls.lock().unwrap().iter().map(|c| c.0.clone()).collect();
    for w in ["chat_send", "mark_channel_read", "mark_read", "download_file", "share_file", "approve", "decline", "react_chat", "propose", "wiki_edit"] {
        assert!(!names.iter().any(|n| n == w), "{w} was called in read-only mode");
    }
}

#[test]
fn login_throttle() {
    let e = boot(false);
    for _ in 0..8 { assert_eq!(req("POST", &format!("{}/api/login", e.base), None, None, None, Some(json!({"password":"bad"}))).code, 401) }
    assert_eq!(req("POST", &format!("{}/api/login", e.base), None, None, None, Some(json!({"password":PW}))).code, 429);
}

fn up(e: &Env, s: &Sess, q: &str, body: &[u8], csrf: bool, origin: Option<&str>) -> R {
    req_x("POST", &format!("{}/api/upload?{q}", e.base), Some(&s.cookie), csrf.then_some(s.csrf.as_str()), origin, Some((body.to_vec(), "application/octet-stream")), &[])
}
fn find_upload(e: &Env) -> Vec<std::path::PathBuf> {
    let root = e.cache.canonicalize().unwrap().join("uploads");
    let mut v = vec![];
    for d in std::fs::read_dir(root).into_iter().flatten().flatten() { for f in std::fs::read_dir(d.path()).unwrap().flatten() { if !f.file_name().to_string_lossy().starts_with('.') { v.push(f.path()) } } }
    v
}
fn jreq(url: &str, body: Value, extra: &[(&str, &str)]) -> R { req_x("POST", url, None, None, None, Some((body.to_string().into_bytes(), "application/json")), extra) }

#[test]
fn upload_flow_and_limits() {
    let e = boot_with(false, |c| c.max_upload = 1024);
    let s = login(&e);
    let _ = first_state(&e, &s);
    let host = e.base.trim_start_matches("http://").to_string();
    let r = up(&e, &s, "name=..%2F..%2Fevil%2Fnotes.txt&ch=t%3AIdeen&text=hi", b"hello", true, Some(&format!("http://{host}")));
    assert_eq!(r.code, 200, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.json()["name"], "notes.txt");
    let sf = e.mock.called("share_file");
    assert_eq!(sf.len(), 1);
    let path = sf[0]["path"].as_str().unwrap();
    assert!(path.starts_with(e.cache.canonicalize().unwrap().join("uploads").to_str().unwrap()) && path.ends_with("/notes.txt"));
    assert_eq!(std::fs::read(path).unwrap(), b"hello");
    assert_eq!(sf[0]["channel"], json!({"kind":"topic","name":"Ideen"}));
    use std::os::unix::fs::PermissionsExt;
    let pdir = std::path::Path::new(path).parent().unwrap();
    assert_eq!(std::fs::metadata(pdir).unwrap().permissions().mode() & 0o777, 0o700);
    assert_eq!(std::fs::metadata(&e.cache).unwrap().permissions().mode() & 0o777, 0o700);
    assert_eq!(std::fs::read_to_string(pdir.join(".id")).unwrap(), MID4);
    let cs = e.mock.called("chat_send");
    assert_eq!((cs[0]["body"].as_str(), cs[0]["channel"].clone()), (Some("[alice] hi"), json!({"kind":"topic","name":"Ideen"})));
    assert_eq!(up(&e, &s, "name=a.bin", b"x", true, None).code, 200);
    assert!(e.mock.called("share_file")[1].get("channel").is_none());
    assert_eq!(e.mock.called("chat_send")[1]["body"], "[alice] \u{1F4CE} a.bin");
    let n_before = e.mock.called("share_file").len();
    assert_eq!(up(&e, &s, "name=big", &vec![0u8; 1025], true, None).code, 413);
    assert_eq!(up(&e, &s, "name=empty", b"", true, None).code, 400);
    assert_eq!(up(&e, &s, "name=x&ch=t%3A", b"x", true, None).code, 400, "bad channel");
    assert_eq!(up(&e, &s, "name=x", b"x", false, None).code, 403);
    assert_eq!(up(&e, &s, "name=x", b"x", true, Some("http://evil.example")).code, 403);
    let r = req_x("POST", &format!("{}/api/upload?name=x", e.base), Some(&s.cookie), Some(&s.csrf), None, Some((b"x".to_vec(), "application/octet-stream")), &[("Sec-Fetch-Site", "cross-site")]);
    assert_eq!(r.code, 403);
    assert_eq!(req_x("POST", &format!("{}/api/upload?name=x", e.base), None, Some(&s.csrf), None, Some((b"x".to_vec(), "x/y")), &[]).code, 401);
    assert_eq!(e.mock.called("share_file").len(), n_before, "rejected uploads never reach the daemon");
    assert_eq!(find_upload(&e).len(), 2, "rejected uploads leave nothing on disk");
}

#[test]
fn upload_refused_read_only() {
    let e = boot(true);
    let s = login(&e);
    let _ = first_state(&e, &s);
    assert_eq!(up(&e, &s, "name=x", b"x", true, None).code, 403);
    assert!(e.mock.called("share_file").is_empty() && find_upload(&e).is_empty());
}

#[test]
fn login_limits_per_user_and_ip() {
    let e = boot(false);
    let url = format!("{}/api/login", e.base);
    for i in 0..20 {
        assert_eq!(jreq(&url, json!({"user":format!("u{i}"),"password":"bad"}), &[("X-Forwarded-For", &format!("10.0.0.{i}"))]).code, 401);
    }
    assert_eq!(jreq(&url, json!({"user":"alice","password":PW}), &[("X-Forwarded-For", "10.9.9.9")]).code, 429, "XFF ignored without --trusted-proxy");
    let e = boot_with(false, |c| c.trusted_proxy = true);
    let url = format!("{}/api/login", e.base);
    for i in 0..20 {
        assert_eq!(jreq(&url, json!({"user":format!("u{i}"),"password":"bad"}), &[("X-Forwarded-For", "9.9.9.9, 10.0.0.1")]).code, 401);
    }
    assert_eq!(jreq(&url, json!({"user":"alice","password":PW}), &[("X-Forwarded-For", "9.9.9.9, 10.0.0.1")]).code, 429);
    assert_eq!(jreq(&url, json!({"user":"alice","password":PW}), &[("X-Forwarded-For", "1.1.1.1, 10.0.0.2")]).code, 200);
}

#[test]
fn logout_closes_event_stream() {
    let e = boot(false);
    let s = login(&e);
    let resp = ureq::get(&format!("{}/api/events", e.base)).set("Cookie", &s.cookie).call().unwrap();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || { for l in BufReader::new(resp.into_reader()).lines() { if l.is_err() { break } } let _ = tx.send(()); });
    std::thread::sleep(std::time::Duration::from_millis(600));
    assert!(rx.try_recv().is_err(), "stream open while logged in");
    let host = e.base.trim_start_matches("http://");
    assert_eq!(req("POST", &format!("{}/api/logout", e.base), Some(&s.cookie), Some(&s.csrf), Some(&format!("http://{host}")), Some(json!({}))).code, 200);
    assert!(rx.recv_timeout(std::time::Duration::from_secs(8)).is_ok(), "stream must end after logout");
}

#[test]
fn host_cookie_when_secure() {
    let e = boot_with(false, |c| c.secure = true);
    let r = req("POST", &format!("{}/api/login", e.base), None, None, None, Some(json!({"password":PW})));
    let sc = r.h("set-cookie");
    assert!(sc.starts_with("__Host-molt_session=") && sc.contains("Secure") && sc.contains("Path=/") && !sc.contains("Domain"), "{sc}");
    let ck = sc.split(';').next().unwrap();
    assert_eq!(req("GET", &format!("{}/api/me", e.base), Some(ck), None, None, None).code, 200);
}

#[test]
fn member_images_need_root() {
    let tmp = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    let dir = tmp.join(format!("img{}", molt_web::auth::rand_hex(4)));
    std::fs::create_dir_all(dir.join("sub")).unwrap();
    std::fs::write(dir.join("sub/b.png"), PNG).unwrap();
    let outside = tmp.join(format!("out{}.png", molt_web::auth::rand_hex(4)));
    std::fs::write(&outside, PNG).unwrap();
    std::os::unix::fs::symlink(&outside, dir.join("sub/link.png")).unwrap();
    let paths = (dir.join("sub/b.png"), dir.join("sub/link.png"), outside.clone());
    let mk = |root: Option<std::path::PathBuf>| {
        let (p1, p2, p3) = paths.clone();
        let h: mock::Handler = Arc::new(move |name, _| Ok(match name {
            "status" => json!({"name":"D","member":"s"}),
            "read_state" => json!({"channels":[],"applied":[]}),
            "list_proposals" => json!({"proposals":[]}), "read_actions" => json!({"actions":[]}), "read_uploads" => json!({"uploads":[]}),
            "read_members" => json!({"members":[{"member":"in","image":p1},{"member":"link","image":p2},{"member":"out","image":p3},{"member":"rel","image":"../x.png"}]}),
            _ => json!({}),
        }));
        let m = mock::start(TOKEN, h);
        let cfg = Config { url: Some(m.url.clone()), token: Some(TOKEN.into()), listen: "127.0.0.1:0".into(),
            users: vec![("alice".into(), molt_web::auth::hash_password(PW, 1000))], cache: dir.join("cache"), poll_ms: 500, image_root: root, ..Config::default() };
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || { molt_web::serve(cfg, Some(tx)).unwrap() });
        let addr = rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
        Env { mock: m, base: format!("http://{addr}"), cache: dir.join("cache") }
    };
    let code = |e: &Env, s: &Sess, n: &str| req("GET", &format!("{}/api/member-image/{n}", e.base), Some(&s.cookie), None, None, None).code;
    let e = mk(Some(dir.clone()));
    let s = login(&e); let _ = first_state(&e, &s);
    assert_eq!(code(&e, &s, "in"), 200);
    assert_eq!(code(&e, &s, "link"), 404, "symlink leaving the root");
    assert_eq!(code(&e, &s, "out"), 404);
    assert_eq!(code(&e, &s, "rel"), 404);
    let e = mk(None);
    let s = login(&e); let _ = first_state(&e, &s);
    assert_eq!(code(&e, &s, "in"), 404, "no root configured: refused");
}
