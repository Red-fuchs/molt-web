use molt_client::mcp::Mcp;
use molt_client::model::*;
use molt_client::text::one;
use serde_json::{json, Value};
use std::collections::HashMap;

pub struct Fetched { pub state: Value, pub files: HashMap<String, FileMeta>, pub images: HashMap<String, String> }

pub fn ckey(c: &Chan) -> String {
    match c { Chan::Group => "g".into(), Chan::Topic(n) => format!("t:{n}"), Chan::Patch(i) => format!("p:{i}") }
}

pub fn is_image_name(n: &str) -> bool {
    let l = n.to_lowercase();
    ["png", "jpg", "jpeg", "gif", "webp"].iter().any(|e| l.rsplit_once('.').is_some_and(|(_, x)| x == *e))
}

const PER_CHAN: usize = 500;
const MAX_BODY: usize = 8000;

/// Cap a message body at `MAX_BODY` chars (the browser re-renders every message on each change).
pub fn cap(s: &str) -> String {
    if s.chars().count() <= MAX_BODY { s.to_string() } else { s.chars().take(MAX_BODY).collect::<String>() + "\n[... truncated]" }
}

/// Copy of the state without fields that change on every poll without being user-visible news (liveness counters, last-seen stamps).
pub fn stable_key(v: &Value) -> String {
    let mut c = v.clone();
    if let Some(h) = c.get_mut("health").and_then(Value::as_object_mut) { h.remove("lag"); h.remove("active_1h"); }
    for m in c.get_mut("members").and_then(Value::as_array_mut).into_iter().flatten() { if let Some(o) = m.as_object_mut() { o.remove("last_seen"); } }
    c.to_string()
}

pub fn build(st: &Value, chat: &Value, props: &Value, acts: &Value, members: &Value, uploads: &Value) -> Fetched {
    let status = parse_status(st);
    let (msgs, chans, wiki_rev) = parse_chat(chat);
    let props: Vec<Prop> = props.get("proposals").and_then(Value::as_array).into_iter().flatten().map(parse_prop).collect();
    let mem = parse_members(members);
    let ups = parse_uploads(uploads);
    let entries = group_channels(&chans, &props, &[]);

    let mut by: HashMap<String, Vec<&Msg>> = HashMap::new();
    for m in &msgs { by.entry(ckey(&m.chan)).or_default().push(m) }
    let mut files = HashMap::new();
    let mut out = vec![];
    for (_, mut v) in by {
        v.sort_by_key(|m| m.ts);
        let skip = v.len().saturating_sub(PER_CHAN);
        for m in v.into_iter().skip(skip) {
            let (tag, body) = split_tag(&m.body);
            let mut j = json!({"id":m.id,"from":m.from,"ts":m.ts,"kind":m.kind,"chan":ckey(&m.chan),"tag":tag,"body":cap(body),
                "quote":m.quote,"reactions":m.reactions});
            if let Some(f) = &m.file {
                let u = ups.iter().find(|u| u.id == m.id);
                j["file"] = json!({"name":f.name,"kind":f.kind,"size":f.size,"image":f.kind.eq_ignore_ascii_case("image") && is_image_name(&f.name),
                    "upload": u.map(|u| json!({"expires_ts":u.expires_ts,"persistent":u.persistent,"availability":u.availability,"local":u.local,"online":u.online,"available":u.available}))});
                files.insert(m.id.clone(), f.clone());
            }
            out.push(j);
        }
    }
    out.sort_by_key(|j| j["ts"].as_i64().unwrap_or(0));

    let chans_j: Vec<Value> = entries.iter().map(|e| json!({"key":ckey(&e.chan),"label":e.label,"section":e.section,"unread":e.unread,"count":e.count,
        "chan": e.chan.to_json().unwrap_or(json!({"kind":"group"}))})).collect();
    let mut sorted: Vec<&Prop> = props.iter().collect();
    sorted.sort_by(|a, b| b.open().cmp(&a.open()).then(b.id.cmp(&a.id)));
    let props_j: Vec<Value> = sorted.iter().map(|p| json!({"id":p.id,"state":p.state,"by":p.by,"op":p.op,"summary":p.summary,
        "approvals":p.approvals,"threshold":p.threshold,"votes":p.votes,"todo":p.todo(),"chan":format!("p:{}", p.id)})).collect();
    let mut images = HashMap::new();
    let mem_j: Vec<Value> = mem.iter().map(|m| {
        if !m.image.is_empty() { images.insert(m.name.clone(), m.image.clone()) ; }
        json!({"name":m.name,"desc":m.desc,"presence":m.presence,"last_seen":m.last_seen,"uploads":m.uploads,"image":!m.image.is_empty()})
    }).collect();
    let todo = acts.get("actions").and_then(Value::as_array).map_or(0, |a| a.iter().filter(|x| x.get("kind").and_then(Value::as_str) == Some("vote")).count());
    let state = json!({"name":status.name,"seat":status.member,"retention_days":st.get("chat_retention_days"),
        "health":{"relays":status.relays,"missing_relays":status.missing_relays,"diverged":status.diverged,"lag":status.lag,"active_1h":status.active_1h},
        "wiki_rev":wiki_rev,"chans":chans_j,"msgs":out,"props":props_j,"members":mem_j,"todo":todo});
    Fetched { state, files, images }
}

pub fn fetch(m: &Mcp) -> Result<Fetched, String> {
    let st = m.call("status", json!({}))?;
    let chat = m.call("read_state", json!({"surface":"chat"}))?;
    let props = m.call("list_proposals", json!({"state":"all"}))?;
    let acts = m.call("read_actions", json!({}))?;
    let members = m.call("read_members", json!({}))?;
    let uploads = m.call("read_uploads", json!({}))?;
    let mut f = build(&st, &chat, &props, &acts, &members, &uploads);
    f.state["name"] = json!(one(f.state["name"].as_str().unwrap_or("")));
    Ok(f)
}

#[cfg(test)]
mod t {
    use super::*;
    #[test]
    fn caps_and_stable() {
        assert!(cap(&"x".repeat(20000)).chars().count() < 8100);
        assert_eq!(cap("short"), "short");
        let a = json!({"health":{"lag":1,"relays":2},"members":[{"name":"a","last_seen":5}]});
        let b = json!({"health":{"lag":9,"relays":2},"members":[{"name":"a","last_seen":6}]});
        assert_eq!(stable_key(&a), stable_key(&b));
        assert_ne!(stable_key(&a), stable_key(&json!({"health":{"lag":9,"relays":3},"members":[]})));
    }
    #[test]
    fn builds_clean_state() {
        let st = json!({"name":"Demo","member":"alice","chat_retention_days":7});
        let chat = json!({"channels":[{"channel":{"kind":"group"},"count":2,"unread":1,"last_ts":5}],"applied":[
            {"id":"m1","from":"alice","ts":10,"kind":"user","body":"[Claude] hi \u{202e}x"},
            {"id":"m2","from":"bob","ts":9,"kind":"user","body":"pic","quote":"m1","file":{"name":"a.PNG","kind":"Image","size":3,"checksum":"AA","key_b64":"SECRETKEY","root":"R"}}]});
        let ups = json!({"uploads":[{"id":"m2","expires_ts":99,"persistent":false,"local":"none","availability":"sharer-only","online":true,"available":true}]});
        let f = build(&st, &chat, &json!({}), &json!({"actions":[{"kind":"vote","proposal":1}]}), &json!({"members":[{"member":"bob","image":"/p/x.png"}]}), &ups);
        let s = f.state.to_string();
        assert!(!s.contains("SECRETKEY") && !s.contains('\u{202e}'));
        assert_eq!(f.state["msgs"][0]["id"], "m2");
        assert_eq!(f.state["msgs"][1]["tag"], "Claude");
        assert_eq!(f.state["msgs"][1]["body"], "hi x");
        assert_eq!(f.state["msgs"][0]["file"]["image"], true);
        assert_eq!(f.state["msgs"][0]["file"]["upload"]["expires_ts"], 99);
        assert_eq!(f.state["todo"], 1);
        assert_eq!(f.files["m2"].checksum, "aa");
        assert_eq!(f.images["bob"], "/p/x.png");
    }
}
