//! Votes, proposals, withdraw and topics against the stateful in-process republic (mock::sim); the live moltd is never contacted.
use molt_client::mock::{self, sim::Sim, Mock};
use molt_web::config::Config;
use serde_json::{json, Value};
use std::io::{BufRead, BufReader};
use std::sync::mpsc;

const TOKEN: &str = "TEST-TOKEN-0123456789";
const PW: &str = "correct horse";
struct Env { mock: Mock, base: String }
struct Sess { cookie: String, csrf: String }

fn boot(read_only: bool) -> Env { boot_with(read_only, 0) }
fn boot_with(read_only: bool, filler: usize) -> Env {
    let mut sim = Sim::new("seat-a");
    sim.add_filler(filler);
    let (h, _) = sim.into_handler(None);
    let m = mock::start(TOKEN, h);
    let cache = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("w{}", molt_web::auth::rand_hex(6)));
    let cfg = Config { url: Some(m.url.clone()), token: Some(TOKEN.into()), listen: "127.0.0.1:0".into(),
        users: vec![("alice".into(), molt_web::auth::hash_password(PW, 1000))], read_only, cache, poll_ms: 300, ..Config::default() };
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || molt_web::serve(cfg, Some(tx)).unwrap());
    let addr = rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
    Env { mock: m, base: format!("http://{addr}") }
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

#[test]
fn vote_requires_confirm_and_checks_state() {
    let e = boot(false);
    let s = login(&e);
    let st = state(&e, &s, |_| true);
    let p4 = st["props"].as_array().unwrap().iter().find(|p| p["id"] == 4).unwrap();
    assert_eq!((p4["todo"].clone(), p4["can_withdraw"].clone()), (json!(true), json!(false)));
    // no confirm / bad csrf / foreign origin / unknown id: nothing reaches the daemon
    assert_eq!(post(&e, &s, "/api/vote", json!({"id":4,"approve":true})).0, 400);
    assert_eq!(post(&e, &s, "/api/vote", json!({"id":4,"approve":true,"confirm":false})).0, 400);
    assert_eq!(post(&e, &s, "/api/vote", json!({"id":4,"confirm":true})).0, 400);
    assert_eq!(post(&e, &s, "/api/vote", json!({"id":99,"approve":true,"confirm":true})).0, 404);
    assert_eq!(call("POST", &format!("{}/api/vote", e.base), Some(&s), false, None, Some(json!({"id":4,"approve":true,"confirm":true}))).0, 403);
    assert_eq!(call("POST", &format!("{}/api/vote", e.base), Some(&s), true, Some("http://evil.example"), Some(json!({"id":4,"approve":true,"confirm":true}))).0, 403);
    assert_eq!(post(&e, &s, "/api/vote", json!({"id":1,"approve":true,"confirm":true})).0, 409, "applied proposal is not open");
    assert!(e.mock.called("approve").is_empty() && e.mock.called("decline").is_empty());
    // a real vote, with a tagged reason
    let (c, j) = post(&e, &s, "/api/vote", json!({"id":4,"approve":true,"note":"passt so","confirm":true}));
    assert_eq!(c, 200, "{j}");
    assert_eq!(j["state"], "applied");
    assert_eq!(e.mock.called("approve")[0], json!({"proposal_id":4,"note":"[alice] passt so"}));
    // already decided/voted: refused locally once the poller saw it
    let st = state(&e, &s, |v| v["props"].as_array().is_some_and(|p| p.iter().any(|x| x["id"] == 4 && x["state"] == "applied")));
    assert!(st["msgs"].as_array().unwrap().iter().any(|m| m["chan"] == "p:4" && m["body"] == "passt so" && m["tag"] == "alice"));
    assert_eq!(post(&e, &s, "/api/vote", json!({"id":4,"approve":false,"confirm":true})).0, 409);
    assert_eq!(e.mock.called("approve").len() + e.mock.called("decline").len(), 1);
}

#[test]
fn decline_without_note_and_detail() {
    let e = boot(false);
    let s = login(&e);
    state(&e, &s, |_| true);
    let (c, d) = call("GET", &format!("{}/api/proposal/4", e.base), Some(&s), false, None, None);
    assert_eq!(c, 200);
    assert!(d["value"].as_str().unwrap().contains("+++ b/neu.md") && d["votes"].as_array().unwrap().len() == 3 && d["todo"] == true);
    assert_eq!(call("GET", &format!("{}/api/proposal/77", e.base), Some(&s), false, None, None).0, 404);
    assert_eq!(call("GET", &format!("{}/api/proposal/4", e.base), None, false, None, None).0, 401);
    assert_eq!(post(&e, &s, "/api/vote", json!({"id":4,"approve":false,"confirm":true})).0, 200);
    assert_eq!(e.mock.called("decline")[0], json!({"proposal_id":4}));
}

#[test]
fn propose_preview_confirm_withdraw() {
    let e = boot(false);
    let s = login(&e);
    state(&e, &s, |_| true);
    let b = json!({"kind":"wiki_new","a":"notizen/idee.md","b":"# Idee\ntext"});
    let (c, pv) = post(&e, &s, "/api/propose/preview", b.clone());
    assert_eq!(c, 200);
    assert!(pv["preview"].as_str().unwrap().contains("notizen/idee.md") && pv["tool"] == "wiki_edit");
    assert_eq!(pv["warnings"], json!([]));
    assert!(e.mock.called("wiki_edit").iter().all(|c| c["dry_run"] == true), "preview only dry-runs");
    assert_eq!(post(&e, &s, "/api/propose", b.clone()).0, 400, "confirm missing");
    for bad in [json!({"kind":"nope"}), json!({"kind":"wiki_new","a":"../x.md","b":"x"}), json!({"kind":"retention","a":"0"}), json!({"kind":"relays","a":"http://x"})] {
        assert_eq!(post(&e, &s, "/api/propose", { let mut b = bad; b["confirm"] = json!(true); b }).0, 400);
    }
    assert!(e.mock.called("wiki_edit").iter().all(|c| c["dry_run"] == true) && e.mock.called("propose").is_empty());
    let mut ok = b.clone(); ok["confirm"] = json!(true);
    let (c, j) = post(&e, &s, "/api/propose", ok.clone());
    assert_eq!(c, 200, "{j}");
    let id = j["id"].as_u64().unwrap();
    assert_eq!(e.mock.called("wiki_edit").last().unwrap(), &json!({"edits":[{"op":"create","path":"notizen/idee.md","content":"# Idee\ntext"}]}));
    // daemon refusal reason is shown verbatim
    let (c, j) = post(&e, &s, "/api/propose", ok);
    assert_eq!(c, 502);
    assert!(j["error"].as_str().unwrap().contains("already exists"), "{j}");
    // the other types
    for (k, a, b, op) in [("note", "Titel", "", "add_note"), ("retention", "14", "", "set_chat_retention"), ("name", "Neu", "", "set_name"), ("charter", "", "Text", "set_charter"),
        ("persist", &"ab".repeat(16), "", "persist"), ("relays", "wss://a.example", "", "set_relays"), ("features", "memory quests", "", "set_features")] {
        let (c, j) = post(&e, &s, "/api/propose", json!({"kind":k,"a":a,"b":b,"confirm":true}));
        assert_eq!(c, 200, "{k}: {j}");
        assert_eq!(e.mock.called("propose").last().unwrap()["payload"]["op"], op);
    }
    // own pending proposal: withdraw needs confirm; someone else's is refused locally
    let st = state(&e, &s, |v| v["props"].as_array().is_some_and(|p| p.iter().any(|x| x["id"] == id)));
    assert_eq!(st["props"].as_array().unwrap().iter().find(|p| p["id"] == id).unwrap()["can_withdraw"], true);
    assert_eq!(post(&e, &s, "/api/withdraw", json!({"id":id})).0, 400);
    assert_eq!(post(&e, &s, "/api/withdraw", json!({"id":4,"confirm":true})).0, 403);
    assert!(e.mock.called("withdraw").is_empty());
    let (c, j) = post(&e, &s, "/api/withdraw", json!({"id":id,"note":"doch nicht","confirm":true}));
    assert_eq!((c, j["state"].clone()), (200, json!("withdrawn")));
    assert_eq!(e.mock.called("withdraw")[0], json!({"proposal_id":id,"note":"[alice] doch nicht"}));
    state(&e, &s, |v| v["props"].as_array().is_some_and(|p| p.iter().any(|x| x["id"] == id && x["state"] == "withdrawn")));
    assert_eq!(post(&e, &s, "/api/withdraw", json!({"id":id,"confirm":true})).0, 409);
}

#[test]
fn topic_creation() {
    let e = boot(false);
    let s = login(&e);
    state(&e, &s, |_| true);
    assert_eq!(post(&e, &s, "/api/topic", json!({"name":"","body":"x"})).0, 400);
    assert_eq!(post(&e, &s, "/api/topic", json!({"name":"x".repeat(65),"body":"x"})).0, 400);
    assert_eq!(post(&e, &s, "/api/topic", json!({"name":"a\nb","body":"x"})).0, 400);
    assert_eq!(post(&e, &s, "/api/topic", json!({"name":"Neu","body":"  "})).0, 400);
    assert_eq!(call("POST", &format!("{}/api/topic", e.base), Some(&s), false, None, Some(json!({"name":"Neu","body":"x"}))).0, 403);
    assert!(e.mock.called("chat_send").is_empty());
    let (c, j) = post(&e, &s, "/api/topic", json!({"name":"  Ideen \u{1b}[31m","body":"Los geht's"}));
    assert_eq!((c, j["key"].clone()), (200, json!("t:Ideen")));
    assert_eq!(e.mock.called("chat_send")[0], json!({"body":"[alice] Los geht's","channel":{"kind":"topic","name":"Ideen"}}));
    let st = state(&e, &s, |v| v["chans"].as_array().is_some_and(|c| c.iter().any(|x| x["key"] == "t:Ideen")));
    assert!(st["chans"].as_array().unwrap().iter().any(|x| x["label"] == "Ideen" && x["section"] == 1));
}

#[test]
fn read_only_refuses_everything() {
    let e = boot(true);
    let s = login(&e);
    state(&e, &s, |_| true);
    for (p, b) in [("/api/vote", json!({"id":4,"approve":true,"confirm":true})), ("/api/withdraw", json!({"id":4,"confirm":true})),
        ("/api/propose", json!({"kind":"note","a":"x","confirm":true})), ("/api/propose/preview", json!({"kind":"note","a":"x"})), ("/api/topic", json!({"name":"x","body":"y"}))] {
        assert_eq!(post(&e, &s, p, b).0, 403, "{p}");
    }
    let names: Vec<String> = e.mock.calls.lock().unwrap().iter().map(|c| c.0.clone()).collect();
    for w in ["chat_send", "approve", "decline", "withdraw", "propose", "wiki_edit"] { assert!(!names.iter().any(|n| n == w), "{w} in read-only mode") }
}

#[test]
fn foreign_rewrite_warning_flow() {
    let e = boot(false);
    let s = login(&e);
    state(&e, &s, |_| true);
    let b = json!({"kind":"wiki_edit","a":"home.md","b":"# Neu\ntext"});
    let (c, pv) = post(&e, &s, "/api/propose/preview", b.clone());
    assert_eq!(c, 200, "{pv}");
    assert_eq!(pv["warnings"][0]["code"], "foreign_rewrite", "{pv}");
    assert!(pv["args"]["edits"][0]["content"].as_str().unwrap().starts_with("---\ntype: meta"), "header kept");
    let n = e.mock.called("wiki_edit").len();
    let mut ok = b.clone(); ok["confirm"] = json!(true);
    // unaccepted warning: refused, nothing proposed
    let (c, j) = post(&e, &s, "/api/propose", ok.clone());
    assert_eq!(c, 409, "{j}");
    assert!(j["error"].as_str().unwrap().contains("foreign_rewrite"));
    assert!(e.mock.called("wiki_edit").iter().all(|c| c["dry_run"] == true));
    ok["accept_warnings"] = json!(["foreign_rewrite"]);
    let (c, j) = post(&e, &s, "/api/propose", ok);
    assert_eq!(c, 200, "{j}");
    assert!(j["id"].as_u64().is_some());
    let last = e.mock.called("wiki_edit").pop().unwrap();
    assert_eq!(last["allow_warnings"], json!(["foreign_rewrite"]));
    assert!(e.mock.called("wiki_edit").len() > n);
}

#[test]
fn proposals_page_past_100_and_version() {
    let e = boot_with(false, 620);
    let s = login(&e);
    let st = state(&e, &s, |v| v["props"].as_array().is_some_and(|p| p.len() > 100));
    assert!(st["props"].as_array().unwrap().len() >= 620);
    assert!(e.mock.called("list_proposals").iter().any(|c| c["cursor"].is_string() || c["cursor"].is_number()), "followed the cursor");
    let r = ureq::get(&format!("{}/api/me", e.base)).set("Cookie", &s.cookie).call().unwrap();
    let j: Value = serde_json::from_str(&r.into_string().unwrap()).unwrap();
    assert!(j["version"].as_str().is_some_and(|v| v.starts_with("0.1.0-")), "{j}");
}

#[test]
fn mentions_poke_after_send_with_gate() {
    let e = boot(false);
    let s = login(&e);
    let st = state(&e, &s, |v| v["poke_enabled"] == json!(true));
    // state carries the extracted mentions (word boundary, no substring hit)
    assert!(st["msgs"].as_array().unwrap().iter().all(|m| m["mentions"].is_array()));
    let (c, j) = post(&e, &s, "/api/send", json!({"body":"@bob @{bob} hallo @seat-a @carol @bobby"}));
    assert_eq!(c, 200, "{j}");
    let r = j["pokes"].as_array().unwrap();
    assert_eq!(r.iter().map(|p| (p["member"].as_str().unwrap(), p["result"].as_str().unwrap())).collect::<Vec<_>>(), [("bob", "sent"), ("carol", "sent")]);
    assert_eq!(j["skipped"], 0);
    let order: Vec<String> = e.mock.calls.lock().unwrap().iter().map(|c| c.0.clone()).filter(|n| n == "chat_send" || n == "poke").collect();
    assert_eq!(order, ["chat_send", "poke", "poke"]);
    assert_eq!(e.mock.called("poke").iter().map(|a| a["member"].clone()).collect::<Vec<_>>(), [json!("bob"), json!("carol")]);
    // second message inside the minute: chat goes out, poke is rate limited locally
    let (c, j) = post(&e, &s, "/api/send", json!({"body":"nochmal @bob"}));
    assert_eq!(c, 200);
    assert_eq!(j["pokes"][0]["result"], "rate_limited");
    assert_eq!(e.mock.called("poke").len(), 2);
    assert_eq!(e.mock.called("chat_send").len(), 2);
    // explicit poke: same gate; unknown member and self refused
    assert_eq!(post(&e, &s, "/api/poke", json!({"member":"carol"})).1["result"], "rate_limited");
    assert_eq!(post(&e, &s, "/api/poke", json!({"member":"nobody"})).0, 400);
    assert_eq!(post(&e, &s, "/api/poke", json!({"member":"seat-a"})).0, 400);
    // own seat is never poked
    let (_, j) = post(&e, &s, "/api/send", json!({"body":"@bob @carol @seat-a"}));
    assert_eq!(j["skipped"], 0);
}

#[test]
fn read_only_refuses_pokes() {
    let e = boot(true);
    let s = login(&e);
    state(&e, &s, |_| true);
    assert_eq!(post(&e, &s, "/api/poke", json!({"member":"bob"})).0, 403);
    assert_eq!(post(&e, &s, "/api/send", json!({"body":"@bob"})).0, 403);
    assert!(e.mock.called("poke").is_empty() && e.mock.called("chat_send").is_empty());
}
