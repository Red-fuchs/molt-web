pub mod auth;
pub mod config;
pub mod files;
pub mod snap;
pub mod upload;

use auth::{Limiter, Sessions};
use axum::body::Body;
use axum::extract::{ConnectInfo, DefaultBodyLimit, Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use config::Config;
use molt_client::mcp::Mcp;
use molt_client::model::{tag_body, FileMeta};
use molt_client::text::clean;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex, RwLock};
use std::time::Duration;
use tokio::sync::{watch, Semaphore};

struct Shared {
    cfg: Config, sessions: Sessions, limiter: Limiter, worker: Arc<Mcp>,
    tx: watch::Sender<Arc<String>>, shutdown: watch::Sender<bool>,
    kdf: Semaphore, uploads: Semaphore, persistent: RwLock<HashSet<String>>,
    files: RwLock<HashMap<String, FileMeta>>, images: RwLock<HashMap<String, String>>,
    msg_ids: RwLock<HashSet<String>>,
    nudge: Mutex<mpsc::Sender<()>>, dl: tokio::sync::Mutex<()>,
}
type S = State<Arc<Shared>>;

struct E(StatusCode, String);
impl IntoResponse for E {
    fn into_response(self) -> Response { (self.0, Json(json!({"error": self.1}))).into_response() }
}
fn e(c: StatusCode, m: &str) -> E { E(c, m.into()) }

const INDEX: &str = include_str!("../web/index.html");
const JS: &str = include_str!("../web/app.js");
const CSS: &str = include_str!("../web/style.css");
const ICON: &str = include_str!("../web/icon.svg");

fn asset(ct: &'static str, body: &'static str) -> Response {
    ([(header::CONTENT_TYPE, ct), (header::CACHE_CONTROL, "no-cache")], body).into_response()
}

async fn sec(mut r: Response) -> Response {
    let h = r.headers_mut();
    let mut set = |k: &'static str, v: &'static str| { h.entry(k).or_insert(HeaderValue::from_static(v)); };
    set("content-security-policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; font-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'");
    set("x-content-type-options", "nosniff");
    set("x-frame-options", "DENY");
    set("referrer-policy", "same-origin");
    set("cross-origin-opener-policy", "same-origin");
    r
}

fn cookie(h: &HeaderMap, name: &str) -> Option<String> {
    h.get(header::COOKIE)?.to_str().ok()?.split(';').filter_map(|p| p.trim().split_once('=')).find(|(k, _)| *k == name).map(|(_, v)| v.to_string())
}

/// Same-origin check for unsafe methods: an Origin header, when present, must match Host.
/// Some browsers send `Origin: null` (privacy settings); then the fetch metadata must say same-origin.
fn origin_ok(h: &HeaderMap) -> bool {
    let ok = origin_ok_inner(h);
    static LAST: AtomicU64 = AtomicU64::new(0);
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
    if !ok && now >= LAST.load(Ordering::Relaxed) + 30 {
        LAST.store(now, Ordering::Relaxed);
        let g = |k: &str| h.get(k).and_then(|v| v.to_str().ok()).unwrap_or("-").chars().take(120).collect::<String>();
        eprintln!("molt-web: origin rejected: origin={} host={} sec-fetch-site={} referer={}", g("origin"), g("host"), g("sec-fetch-site"), g("referer"));
    }
    ok
}
fn origin_ok_inner(h: &HeaderMap) -> bool {
    let g = |k: &str| h.get(k).and_then(|v| v.to_str().ok());
    // Fetch metadata is set by the browser itself and can't be forged by a page: authoritative when present.
    if let Some(sfs) = g("sec-fetch-site") { return sfs == "same-origin" }
    let Some(o) = g("origin") else { return true };
    o.split_once("://").is_some_and(|(_, hh)| hh == g("host").unwrap_or(""))
}

fn cname(secure: bool) -> &'static str { if secure { "__Host-molt_session" } else { "molt_session" } }

fn client_ip(h: &HeaderMap, peer: SocketAddr, trusted: bool) -> String {
    if trusted && let Some(ip) = h.get("x-forwarded-for").and_then(|v| v.to_str().ok()).and_then(|v| v.rsplit(',').next()).map(str::trim).filter(|v| v.parse::<std::net::IpAddr>().is_ok()) { return ip.to_string() }
    peer.ip().to_string()
}

fn guard(st: &Shared, h: &HeaderMap, write: bool) -> Result<auth::Session, E> {
    let s = cookie(h, cname(st.cfg.secure)).and_then(|t| st.sessions.get(&t)).ok_or_else(|| e(StatusCode::UNAUTHORIZED, "nicht angemeldet"))?;
    if write {
        if !origin_ok(h) { return Err(e(StatusCode::FORBIDDEN, "Origin stimmt nicht")) }
        let ok = h.get("x-csrf-token").and_then(|v| v.to_str().ok()).is_some_and(|t| auth::ct_eq(t, &s.csrf));
        if !ok { return Err(e(StatusCode::FORBIDDEN, "CSRF-Token fehlt oder falsch")) }
        if st.cfg.read_only { return Err(e(StatusCode::FORBIDDEN, "Nur-Lesen-Modus")) }
    }
    Ok(s)
}

fn me_json(st: &Shared, s: &auth::Session) -> Value {
    json!({"user":s.user,"tag":s.user,"csrf":s.csrf,"read_only":st.cfg.read_only,"downloads":st.cfg.downloads,"max_upload":st.cfg.max_upload})
}

async fn login(State(st): S, ConnectInfo(peer): ConnectInfo<SocketAddr>, h: HeaderMap, Json(b): Json<Value>) -> Result<Response, E> {
    if !origin_ok(&h) { return Err(e(StatusCode::FORBIDDEN, "Origin stimmt nicht")) }
    let pw = b["password"].as_str().unwrap_or("").to_string();
    let user = b["user"].as_str().map(str::trim).filter(|u| !u.is_empty()).map(str::to_string)
        .or_else(|| (st.cfg.users.len() == 1).then(|| st.cfg.users[0].0.clone())).unwrap_or_default();
    // count the attempt before any KDF work: per client IP and per login name
    let (ikey, ukey) = (format!("ip:{}", client_ip(&h, peer, st.cfg.trusted_proxy)), format!("u:{}", user.chars().take(64).collect::<String>()));
    if !st.limiter.attempt(&ikey, 20) || !st.limiter.attempt(&ukey, 8) { return Err(e(StatusCode::TOO_MANY_REQUESTS, "zu viele Fehlversuche, bitte eine Minute warten")) }
    let stored = st.cfg.users.iter().find(|(n, _)| *n == user).map(|(_, h)| h.clone());
    // same cost as a real check for unknown names
    let iters = st.cfg.users.first().and_then(|u| config::hash_iters(&u.1)).unwrap_or(auth::ITERS);
    let _permit = st.kdf.acquire().await.map_err(|_| e(StatusCode::INTERNAL_SERVER_ERROR, "intern"))?;
    let ok = tokio::task::spawn_blocking(move || {
        // run the KDF even for unknown users so timing does not reveal valid names
        let dummy = format!("pbkdf2-sha256${iters}$00${}", "0".repeat(64));
        let r = auth::verify_password(&pw, stored.as_deref().unwrap_or(&dummy));
        r && stored.is_some()
    }).await.unwrap_or(false);
    if !ok { return Err(e(StatusCode::UNAUTHORIZED, "Anmeldung fehlgeschlagen")) }
    st.limiter.clear(&ukey);
    let (tok, s) = st.sessions.create(&user);
    let ck = format!("{}={tok}; HttpOnly; SameSite=Strict; Path=/; Max-Age=604800{}", cname(st.cfg.secure), if st.cfg.secure { "; Secure" } else { "" });
    Ok(([(header::SET_COOKIE, ck)], Json(me_json(&st, &s))).into_response())
}

async fn logout(State(st): S, h: HeaderMap) -> Result<Response, E> {
    let _ = guard(&st, &h, false)?;
    if !origin_ok(&h) { return Err(e(StatusCode::FORBIDDEN, "Origin stimmt nicht")) }
    if let Some(t) = cookie(&h, cname(st.cfg.secure)) { st.sessions.drop(&t) }
    let ck = format!("{}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0{}", cname(st.cfg.secure), if st.cfg.secure { "; Secure" } else { "" });
    Ok(([(header::SET_COOKIE, ck)], Json(json!({"ok":true}))).into_response())
}

async fn me(State(st): S, h: HeaderMap) -> Result<Json<Value>, E> { let s = guard(&st, &h, false)?; Ok(Json(me_json(&st, &s))) }

async fn events(State(st): S, h: HeaderMap) -> Result<Response, E> {
    guard(&st, &h, false)?;
    let tok = cookie(&h, cname(st.cfg.secure)).unwrap_or_default();
    let (rx, sd) = (st.tx.subscribe(), st.shutdown.subscribe());
    let stream = futures_util::stream::unfold((rx, sd, true, st.clone(), tok), |(mut rx, mut sd, first, st, tok)| async move {
        loop {
            // the session is re-checked for every event and every few seconds: logout/expiry closes the stream
            if st.sessions.get(&tok).is_none() || *sd.borrow() { return None }
            if first { break }
            tokio::select! {
                r = rx.changed() => { if r.is_err() { return None } break }
                _ = sd.changed() => return None,
                _ = tokio::time::sleep(SSE_RECHECK) => {}
            }
        }
        let v = rx.borrow_and_update().clone();
        Some((Ok::<_, Infallible>(Event::default().event("state").data(v.as_str())), (rx, sd, false, st, tok)))
    });
    Ok(Sse::new(stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(15))).into_response())
}

const SSE_RECHECK: Duration = Duration::from_secs(2);

fn chan_arg(v: &Value) -> Result<Option<Value>, E> {
    match v.get("kind").and_then(Value::as_str) {
        None | Some("group") => Ok(None),
        Some("topic") => {
            let n = v.get("name").and_then(Value::as_str).unwrap_or("").trim();
            if n.is_empty() || n.chars().count() > 64 || clean(n) != n || n.contains('\n') { return Err(e(StatusCode::BAD_REQUEST, "ungültiger Themenname")) }
            Ok(Some(json!({"kind":"topic","name":n})))
        }
        Some("patch") => v.get("id").and_then(Value::as_u64).map(|i| Some(json!({"kind":"patch","id":i}))).ok_or_else(|| e(StatusCode::BAD_REQUEST, "Vorschlags-ID fehlt")),
        _ => Err(e(StatusCode::BAD_REQUEST, "unbekannter Kanal")),
    }
}

async fn call(st: &Shared, name: &'static str, args: Value) -> Result<Value, E> {
    let m = st.worker.clone();
    tokio::task::spawn_blocking(move || m.call(name, args)).await.map_err(|_| e(StatusCode::INTERNAL_SERVER_ERROR, "intern"))?
        .map_err(|x| E(StatusCode::BAD_GATEWAY, public_err(&x)))
}

/// Transport/HTTP failures are logged but never shown to the browser (they name hosts and ports).
pub fn public_err(x: &str) -> String {
    if x.starts_with("transport:") || x.starts_with("HTTP ") { eprintln!("molt-web: moltd call failed: {}", molt_client::text::one(x)); "moltd nicht erreichbar".into() } else { molt_client::text::one(x) }
}

async fn send(State(st): S, h: HeaderMap, Json(b): Json<Value>) -> Result<Json<Value>, E> {
    let s = guard(&st, &h, true)?;
    let body = clean(b["body"].as_str().unwrap_or("")).trim_end().to_string();
    if body.trim().is_empty() { return Err(e(StatusCode::BAD_REQUEST, "leere Nachricht")) }
    if body.chars().count() > 16000 { return Err(e(StatusCode::BAD_REQUEST, "Nachricht zu lang")) }
    let mut a = json!({"body": tag_body(&body, &s.user)});
    if let Some(c) = chan_arg(&b["channel"])? { a["channel"] = c }
    if let Some(q) = b["quote"].as_str() {
        if !st.msg_ids.read().unwrap().contains(q) { return Err(e(StatusCode::BAD_REQUEST, "zitierte Nachricht unbekannt")) }
        a["quote"] = json!(q);
    }
    call(&st, "chat_send", a).await?;
    let _ = st.nudge.lock().unwrap().send(());
    Ok(Json(json!({"ok":true})))
}

fn key_chan(k: &str) -> Value {
    if let Some(n) = k.strip_prefix("t:") { json!({"kind":"topic","name":n}) }
    else if let Some(i) = k.strip_prefix("p:").and_then(|i| i.parse::<u64>().ok()) { json!({"kind":"patch","id":i}) }
    else { json!({"kind":"group"}) }
}

async fn upload(State(st): S, h: HeaderMap, Query(q): Query<HashMap<String, String>>, body: Body) -> Result<Json<Value>, E> {
    use futures_util::StreamExt;
    use tokio::io::AsyncWriteExt;
    let s = guard(&st, &h, true)?;
    let len: u64 = h.get(header::CONTENT_LENGTH).and_then(|v| v.to_str().ok()).and_then(|v| v.parse().ok()).ok_or_else(|| e(StatusCode::LENGTH_REQUIRED, "Content-Length fehlt"))?;
    if len == 0 { return Err(e(StatusCode::BAD_REQUEST, "leere Datei")) }
    if len > st.cfg.max_upload { return Err(e(StatusCode::PAYLOAD_TOO_LARGE, &format!("Datei zu groß (max. {} MB)", st.cfg.max_upload >> 20))) }
    let name = upload::sanitize_name(q.get("name").map_or("", String::as_str));
    let chan = chan_arg(&key_chan(q.get("ch").map_or("g", String::as_str)))?;
    let text = clean(q.get("text").map_or("", String::as_str)).trim().chars().take(2000).collect::<String>();
    let _permit = st.uploads.acquire().await.map_err(|_| e(StatusCode::INTERNAL_SERVER_ERROR, "intern"))?;
    let dir = st.cfg.cache.join("uploads").join(auth::rand_hex(16));
    let mk = |d: &std::path::Path| { use std::os::unix::fs::DirBuilderExt; std::fs::DirBuilder::new().recursive(true).mode(0o700).create(d) };
    mk(&dir).map_err(|_| e(StatusCode::INTERNAL_SERVER_ERROR, "Upload-Verzeichnis nicht anlegbar"))?;
    let path = dir.join(&name);
    let fail = |dir: &std::path::Path, c: StatusCode, m: &str| { let _ = std::fs::remove_dir_all(dir); e(c, m) };
    let f = { use std::os::unix::fs::OpenOptionsExt; std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&path) }
        .map_err(|_| fail(&dir, StatusCode::INTERNAL_SERVER_ERROR, "Datei nicht anlegbar"))?;
    let mut f = tokio::fs::File::from_std(f);
    let (mut total, mut stream) = (0u64, body.into_data_stream());
    while let Some(chunk) = stream.next().await {
        let c = chunk.map_err(|_| fail(&dir, StatusCode::BAD_REQUEST, "Upload abgebrochen"))?;
        total += c.len() as u64;
        if total > st.cfg.max_upload || total > len { return Err(fail(&dir, StatusCode::PAYLOAD_TOO_LARGE, "Datei zu groß")) }
        f.write_all(&c).await.map_err(|_| fail(&dir, StatusCode::INTERNAL_SERVER_ERROR, "Schreiben fehlgeschlagen"))?;
    }
    f.flush().await.map_err(|_| fail(&dir, StatusCode::INTERNAL_SERVER_ERROR, "Schreiben fehlgeschlagen"))?;
    drop(f);
    if total != len { return Err(fail(&dir, StatusCode::BAD_REQUEST, "Upload unvollständig")) }
    let mut a = json!({"path": path.to_string_lossy()});
    if let Some(c) = &chan { a["channel"] = c.clone() }
    let r = match call(&st, "share_file", a).await { Ok(r) => r, Err(x) => { let _ = std::fs::remove_dir_all(&dir); return Err(x) } };
    let id = r.get("id").and_then(Value::as_str).filter(|i| i.len() == 32 && i.bytes().all(|c| c.is_ascii_hexdigit())).map(str::to_string);
    if let Some(i) = &id { let _ = std::fs::write(dir.join(".id"), i); }
    // a share has no text of its own: a tagged line next to it says who shared it
    let line = if text.is_empty() { format!("📎 {name}") } else { text };
    let mut m = json!({"body": tag_body(&line, &s.user)});
    if let Some(c) = chan { m["channel"] = c }
    let sent = call(&st, "chat_send", m).await.is_ok();
    let _ = st.nudge.lock().unwrap().send(());
    Ok(Json(json!({"ok":true,"id":id,"name":name,"tagged":sent})))
}

async fn mark_read(State(st): S, h: HeaderMap, Json(b): Json<Value>) -> Result<Json<Value>, E> {
    guard(&st, &h, true)?;
    let a = chan_arg(&b["channel"])?.map_or(json!({}), |c| json!({"channel": c}));
    call(&st, "mark_channel_read", a).await?;
    let _ = st.nudge.lock().unwrap().send(());
    Ok(Json(json!({"ok":true})))
}

fn blob(ct: &'static str, b: Vec<u8>, name: Option<&str>) -> Response {
    let mut r = ([(header::CONTENT_TYPE, ct), (header::CACHE_CONTROL, "private, max-age=300")], b).into_response();
    if let Some(n) = name {
        let safe: String = n.chars().filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_')).collect();
        r.headers_mut().insert(header::CONTENT_DISPOSITION, HeaderValue::from_str(&format!("attachment; filename=\"{}\"", if safe.is_empty() { "datei".into() } else { safe })).unwrap());
    }
    r.headers_mut().insert("content-security-policy", HeaderValue::from_static("sandbox; default-src 'none'"));
    r
}

async fn file(State(st): S, h: HeaderMap, Path(id): Path<String>, axum::extract::Query(q): axum::extract::Query<HashMap<String, String>>) -> Result<Response, E> {
    guard(&st, &h, false)?;
    if !st.cfg.downloads { return Err(e(StatusCode::FORBIDDEN, "Datei-Downloads sind deaktiviert")) }
    if id.len() != 32 || !id.bytes().all(|c| c.is_ascii_hexdigit()) { return Err(e(StatusCode::BAD_REQUEST, "ungültige Datei-ID")) }
    let meta = st.files.read().unwrap().get(&id).cloned().ok_or_else(|| e(StatusCode::NOT_FOUND, "Datei unbekannt oder abgelaufen"))?;
    let _g = st.dl.lock().await;
    let (m, cache, max, id2, meta2, to) = (st.worker.clone(), st.cfg.cache.clone(), st.cfg.max_file, id.clone(), meta.clone(), st.cfg.dl_timeout);
    let path = tokio::task::spawn_blocking(move || files::ensure(&m, &cache, &id2, &meta2, max, to)).await
        .map_err(|_| e(StatusCode::INTERNAL_SERVER_ERROR, "intern"))?.map_err(|x| E(StatusCode::BAD_GATEWAY, x))?;
    let bytes = std::fs::read(&path).map_err(|_| e(StatusCode::BAD_GATEWAY, "Datei nicht lesbar"))?;
    let want_dl = q.contains_key("dl");
    match files::magic(&bytes) {
        Some(ct) if !want_dl && snap::is_image_name(&meta.name) => Ok(blob(ct, bytes, None)),
        _ => Ok(blob("application/octet-stream", bytes, Some(&meta.name))),
    }
}

async fn member_image(State(st): S, h: HeaderMap, Path(name): Path<String>) -> Result<Response, E> {
    guard(&st, &h, false)?;
    let nf = || e(StatusCode::NOT_FOUND, "kein Bild");
    let root = st.cfg.image_root.clone().ok_or_else(nf)?;
    let p = st.images.read().unwrap().get(&name).cloned().ok_or_else(nf)?;
    let b = tokio::task::spawn_blocking(move || {
        let (root, p) = (std::fs::canonicalize(root).ok()?, std::fs::canonicalize(p).ok()?);
        if !p.starts_with(&root) || !std::fs::metadata(&p).ok()?.is_file() { return None }
        std::fs::read(&p).ok().filter(|b| b.len() <= 4 << 20)
    }).await.ok().flatten().ok_or_else(nf)?;
    files::magic(&b).map(|ct| blob(ct, b, None)).ok_or_else(nf)
}

fn poller(st: Arc<Shared>, m: Mcp, rx: mpsc::Receiver<()>) {
    let (mut good, mut last, mut rev, mut last_err) = (json!({"loading":true}), String::new(), 0u64, String::new());
    let mut next_clean = std::time::Instant::now();
    loop {
        let mut v = match snap::fetch(&m) {
            Ok(f) => {
                *st.files.write().unwrap() = f.files;
                *st.images.write().unwrap() = f.images;
                *st.msg_ids.write().unwrap() = f.state["msgs"].as_array().into_iter().flatten().filter_map(|x| x["id"].as_str().map(str::to_string)).collect();
                *st.persistent.write().unwrap() = f.state["msgs"].as_array().into_iter().flatten()
                    .filter(|x| x["file"]["upload"]["persistent"] == json!(true)).filter_map(|x| x["id"].as_str().map(str::to_string)).collect();
                good = f.state.clone();
                last_err.clear();
                f.state
            }
            Err(err) => {
                let p = public_err(&err);
                if p != last_err { eprintln!("molt-web: poll failed: {p}"); last_err = p.clone() }
                let mut v = good.clone(); v["err"] = json!(p); v
            }
        };
        if std::time::Instant::now() >= next_clean && good.get("loading").is_none() {
            next_clean = std::time::Instant::now() + Duration::from_secs(600);
            let days = good["retention_days"].as_u64().filter(|d| *d > 0).unwrap_or(7);
            let n = files::cleanup(&st.cfg.cache, Duration::from_secs(days * 86400), &st.persistent.read().unwrap(), std::time::SystemTime::now());
            if n > 0 { eprintln!("molt-web: cache cleanup removed {n} entries") }
        }
        let key = snap::stable_key(&v);
        if key != last {
            last = key;
            rev += 1;
            v["rev"] = json!(rev);
            let _ = st.tx.send(Arc::new(v.to_string()));
        }
        let _ = rx.recv_timeout(Duration::from_millis(st.cfg.poll_ms));
        while rx.try_recv().is_ok() {}
    }
}

fn router(st: Arc<Shared>) -> Router {
    Router::new()
        .route("/", get(|| async { asset("text/html; charset=utf-8", INDEX) }))
        .route("/app.js", get(|| async { asset("text/javascript; charset=utf-8", JS) }))
        .route("/style.css", get(|| async { asset("text/css; charset=utf-8", CSS) }))
        .route("/icon.svg", get(|| async { asset("image/svg+xml", ICON) }))
        .route("/api/login", post(login))
        .route("/api/logout", post(logout))
        .route("/api/me", get(me))
        .route("/api/events", get(events))
        .route("/api/send", post(send))
        .route("/api/mark_read", post(mark_read))
        .route("/api/upload", post(upload))
        .route("/api/file/{id}", get(file))
        .route("/api/member-image/{name}", get(member_image))
        .layer(DefaultBodyLimit::max(128 * 1024))
        .layer(axum::middleware::map_response(sec))
        .with_state(st)
}

/// Blocking server. `ready` receives the bound address (used by tests with port 0).
pub fn serve(mut cfg: Config, ready: Option<mpsc::Sender<SocketAddr>>) -> Result<(), String> {
    let addr: SocketAddr = cfg.listen.parse().map_err(|_| format!("--listen: ungültige Adresse {}", cfg.listen))?;
    if !addr.ip().is_loopback() { eprintln!("molt-web: Warnung: lauscht auf {addr} (nicht nur lokal) - HTTPS-Proxy davor setzen und --secure-cookie nutzen") }
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        std::fs::DirBuilder::new().recursive(true).mode(0o700).create(&cfg.cache).map_err(|e| format!("{}: {e}", cfg.cache.display()))?;
        std::fs::set_permissions(&cfg.cache, std::fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
    }
    cfg.cache = std::fs::canonicalize(&cfg.cache).map_err(|e| e.to_string())?;
    let mk = || Mcp::resolve(cfg.url.clone(), cfg.token.clone());
    let (poll, worker) = (mk()?, mk()?);
    let (ntx, nrx) = mpsc::channel();
    let (tx, _rx) = watch::channel(Arc::new(json!({"loading":true}).to_string()));
    let (sdtx, _sdrx) = watch::channel(false);
    let st = Arc::new(Shared { cfg: cfg.clone(), sessions: Sessions::default(), limiter: Limiter::default(), shutdown: sdtx, kdf: Semaphore::new(2), uploads: Semaphore::new(2), persistent: Default::default(), worker: Arc::new(worker), tx,
        files: Default::default(), images: Default::default(), msg_ids: Default::default(), nudge: Mutex::new(ntx), dl: Default::default() });
    let st2 = st.clone();
    std::thread::spawn(move || poller(st2, poll, nrx));
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().worker_threads(2).build().map_err(|e| e.to_string())?;
    rt.block_on(async move {
        let l = tokio::net::TcpListener::bind(addr).await.map_err(|e| format!("{addr}: {e}"))?;
        let a = l.local_addr().map_err(|e| e.to_string())?;
        if !cfg.read_only { eprintln!("molt-web: note: polling read_state sends read receipts for messages the daemon returns (same as any chat read)") }
        eprintln!("molt-web: http://{a}  ({}{})", if cfg.read_only { "read-only" } else { "read-write" }, if cfg.downloads { ", downloads on" } else { "" });
        if let Some(r) = ready { let _ = r.send(a); }
        let sd = st.shutdown.clone();
        let sig = async move {
            let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).ok();
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = async { match term.as_mut() { Some(t) => { t.recv().await; } None => std::future::pending().await } } => {}
            }
            let _ = sd.send(true);
            // open streams close within the recheck interval; don't hang on stragglers
            tokio::spawn(async { tokio::time::sleep(Duration::from_secs(5)).await; std::process::exit(0) });
        };
        axum::serve(l, router(st).into_make_service_with_connect_info::<SocketAddr>()).with_graceful_shutdown(sig).await.map_err(|e| e.to_string())
    })
}

#[cfg(test)]
mod origin_t {
    use super::*;
    fn hm(kv: &[(&'static str, &'static str)]) -> HeaderMap { let mut h = HeaderMap::new(); for (k, v) in kv { h.insert(*k, HeaderValue::from_static(v)); } h }
    #[test]
    fn origin_rules() {
        assert!(origin_ok(&hm(&[("host", "127.0.0.1:8480"), ("origin", "http://127.0.0.1:8480")])));
        assert!(!origin_ok(&hm(&[("host", "127.0.0.1:8480"), ("origin", "http://evil.example")])));
        assert!(origin_ok(&hm(&[("host", "127.0.0.1:8480"), ("origin", "null"), ("sec-fetch-site", "same-origin")])));
        assert!(!origin_ok(&hm(&[("host", "127.0.0.1:8480"), ("origin", "null"), ("sec-fetch-site", "cross-site")])));
        assert!(!origin_ok(&hm(&[("host", "127.0.0.1:8480"), ("origin", "null")])));
        // Chrome sometimes drops the port from Origin; fetch metadata decides
        assert!(origin_ok(&hm(&[("host", "127.0.0.1:8480"), ("origin", "http://127.0.0.1"), ("sec-fetch-site", "same-origin")])));
        assert!(!origin_ok(&hm(&[("host", "127.0.0.1:8480"), ("origin", "http://127.0.0.1:8480"), ("sec-fetch-site", "cross-site")])));
        assert!(!origin_ok(&hm(&[("host", "127.0.0.1:8480"), ("origin", "http://127.0.0.1:8480"), ("sec-fetch-site", "same-site")])));
        assert!(origin_ok(&hm(&[("host", "127.0.0.1:8480")])));
    }
}
