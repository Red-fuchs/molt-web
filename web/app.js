'use strict';
// All server content is untrusted: it is only ever inserted via textContent / createTextNode.
const $ = s => document.querySelector(s);
const H = (tag, attrs, ...kids) => {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) { if (k === 'class') e.className = v; else if (k.startsWith('on')) e.addEventListener(k.slice(2), v); else if (v !== null && v !== undefined && v !== false) e.setAttribute(k, v === true ? '' : v); }
  for (const c of kids.flat()) if (c !== null && c !== undefined && c !== false) e.append(c.nodeType ? c : document.createTextNode(String(c)));
  return e;
};
const store = {
  get(k, d) { try { return localStorage.getItem(k) ?? d; } catch { return d; } },
  set(k, v) { try { localStorage.setItem(k, v); } catch {} },
};
const S = { me: null, s: null, cur: 'g', view: 'chat', quote: null, extra: [], seen: null, att: null, pend: {}, xhr: null, retry: 0, todo: 0, es: null, sending: false };

const toast = (t, bad) => { const e = $('#toast'); e.textContent = t; e.className = bad ? 'bad' : ''; clearTimeout(toast.t); toast.t = setTimeout(() => e.className = 'hidden', 3500); };
async function api(path, body) {
  const o = body === undefined ? {} : { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': S.me?.csrf || '' }, body: JSON.stringify(body) };
  const r = await fetch(path, o);
  const j = await r.json().catch(() => ({}));
  if (r.status === 401 && path !== '/api/login') { showLogin(); throw new Error('nicht angemeldet'); }
  if (!r.ok) throw new Error(j.error || ('HTTP ' + r.status));
  return j;
}

// ---- login ----
function showLogin() { if (S.es) { S.es.close(); S.es = null; } $('#app').classList.add('hidden'); $('#login').classList.remove('hidden'); $('#lp').focus(); }
$('#loginform').addEventListener('submit', async ev => {
  ev.preventDefault(); $('#lerr').textContent = '';
  try { S.me = await api('/api/login', { user: $('#lu').value, password: $('#lp').value }); $('#lp').value = ''; start(); }
  catch (e) { $('#lerr').textContent = e.message; }
});
$('#logout').addEventListener('click', async () => { try { await api('/api/logout', {}); } catch {} location.reload(); });

// ---- helpers ----
const chanObj = k => k === 'g' ? { kind: 'group' } : k.startsWith('t:') ? { kind: 'topic', name: k.slice(2) } : { kind: 'patch', id: +k.slice(2) };
const hue = n => { let h = 0; for (const c of n) h = (h * 31 + c.codePointAt(0)) % 360; return h; };
function avatar(name) {
  const m = S.s?.members.find(x => x.name === name);
  if (m?.image) { const i = H('img', { class: 'av', alt: '', loading: 'lazy', src: '/api/member-image/' + encodeURIComponent(name) }); i.addEventListener('error', () => i.replaceWith(initial(name))); return i; }
  return initial(name);
}
function initial(name) { const a = H('span', { class: 'av' }, [...name.trim()][0]?.toUpperCase() || '?'); a.style.background = `hsl(${hue(name)} 45% 42%)`; return a; }
const fmtTime = ts => new Date(ts * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
const fmtDay = ts => new Date(ts * 1000).toLocaleDateString([], { weekday: 'long', day: 'numeric', month: 'long' });
const fmtSize = n => n < 1024 ? n + ' B' : n < 1048576 ? (n / 1024).toFixed(1) + ' KB' : (n / 1048576).toFixed(1) + ' MB';
function fmtLeft(sec) { if (sec <= 0) return 'abgelaufen'; const d = Math.floor(sec / 86400), h = Math.floor(sec % 86400 / 3600), m = Math.floor(sec % 3600 / 60); return d ? `${d} T ${h} Std` : h ? `${h} Std ${m} Min` : `${m} Min`; }

// ---- message body: ``` fences -> <pre>, http(s) links, everything else plain text ----
const URL_RE = /https?:\/\/[^\s<>"]+/g;
function linkify(t) {
  const out = []; let last = 0;
  for (const m of t.matchAll(URL_RE)) {
    let u = m[0]; const trail = u.match(/[.,;:!?)\]}'"]+$/); if (trail) u = u.slice(0, -trail[0].length);
    out.push(t.slice(last, m.index));
    try { const p = new URL(u); if (p.protocol === 'http:' || p.protocol === 'https:') out.push(H('a', { href: p.href, target: '_blank', rel: 'noopener noreferrer nofollow' }, u)); else out.push(u); } catch { out.push(u); }
    last = m.index + u.length;
  }
  out.push(t.slice(last)); return out;
}
function renderBody(body) {
  const box = H('div', { class: 'txt' });
  let pos = 0;
  for (;;) {
    const open = body.indexOf('```', pos);
    const close = open < 0 ? -1 : body.indexOf('```', open + 3);
    if (open < 0 || close < 0) break;
    if (open > pos) box.append(...linkify(body.slice(pos, open).replace(/\n$/, '')));
    let code = body.slice(open + 3, close);
    const nl = code.indexOf('\n');
    if (nl >= 0 && !/\s/.test(code.slice(0, nl).trim())) code = code.slice(nl + 1); // drop a language tag line
    box.append(H('pre', {}, H('code', {}, code.replace(/\n$/, ''))));
    pos = close + 3; if (body[pos] === '\n') pos++;
  }
  if (pos < body.length) box.append(...linkify(body.slice(pos)));
  return box;
}
function renderFile(m) {
  const f = m.file, u = f.upload, box = H('div', { class: 'file' });
  const dl = S.me.downloads && u && u.available !== false;
  if (f.image && dl) box.append(H('a', { href: `/api/file/${m.id}?dl=1`, target: '_blank', rel: 'noopener' }, H('img', { src: `/api/file/${m.id}`, alt: f.name, loading: 'lazy' })));
  const info = [f.name, fmtSize(f.size)];
  if (!u) info.push('nicht mehr verfügbar (abgelaufen oder gelöscht)');
  else {
    info.push(u.persistent ? 'dauerhaft gespeichert' : 'temporär, ' + (u.expires_ts ? 'läuft ab in ' + fmtLeft(u.expires_ts - Date.now() / 1000) : 'Ablauf unbekannt'));
    if (u.availability) info.push(u.availability + (u.online ? '' : ', Absender offline'));
  }
  box.append(dl && !f.image ? H('a', { href: `/api/file/${m.id}?dl=1`, target: '_blank', rel: 'noopener' }, info.join(' · ')) : info.join(' · '));
  return box;
}

// ---- render ----
function chanEntries() {
  const e = S.s.chans.slice();
  for (const n of S.extra) if (!e.some(x => x.key === 't:' + n)) e.push({ key: 't:' + n, label: n + ' (neu)', section: 1, unread: 0, count: 0 });
  return e;
}
const SECTIONS = ['', 'Themen', 'Offene Vorschläge', 'Erledigte Vorschläge'];
function renderSide() {
  const s = S.s;
  $('#rname').textContent = s.name || 'Molt';
  const hl = s.health || {};
  $('#health').textContent = s.err ? '⚠' : (hl.missing_relays || hl.diverged) ? '●' : '';
  $('#health').title = s.err || `Relays: ${hl.relays}, fehlend: ${hl.missing_relays}`;
  const box = $('#chans'); box.replaceChildren();
  let sec = -1;
  for (const c of chanEntries()) {
    if (S.view === 'props' && c.section < 2) continue;
    if (c.section !== sec) { sec = c.section; if (SECTIONS[sec]) box.append(H('div', { class: 'sec' }, SECTIONS[sec])); }
    box.append(H('div', { class: 'ch' + (c.key === S.cur ? ' on' : ''), onclick: () => { S.cur = c.key; S.view = 'chat'; S.quote = null; render(); $('#side').classList.remove('open'); $('#input').focus(); } },
      H('span', { class: 'l' }, (c.section === 1 ? '# ' : '') + c.label), c.unread ? H('span', { class: 'badge' }, c.unread) : null));
  }
  const mem = $('#members'); mem.replaceChildren();
  for (const m of s.members) mem.append(H('div', { class: 'mem', title: m.desc || '' }, avatar(m.name), H('span', {}, m.name), H('span', { class: 'dot p' + m.presence })));
  const t = $('#todo'); t.textContent = s.todo; t.classList.toggle('hidden', !s.todo);
  document.querySelectorAll('#tabs button').forEach(b => b.classList.toggle('on', b.dataset.view === S.view));
  const un = s.chans.reduce((a, c) => a + c.unread, 0);
  document.title = (un ? `(${un}) ` : '') + (s.name || 'Molt');
}
let lastKey = '';
function renderMsgs() {
  const s = S.s, list = $('#msgs');
  const ent = chanEntries().find(c => c.key === S.cur);
  $('#ctitle').textContent = ent ? ent.label : S.cur;
  $('#cinfo').textContent = ent ? `${ent.count} Nachrichten` : '';
  $('#markread').classList.toggle('hidden', !!(S.me.read_only) || !(ent && ent.unread));
  const msgs = s.msgs.filter(m => m.chan === S.cur);
  const byId = Object.fromEntries(s.msgs.map(m => [m.id, m]));
  const key = S.cur + '|' + Object.keys(S.pend).join() + '|' + JSON.stringify(msgs.map(m => [m.id, m.reactions, m.file?.upload?.local, m.file?.upload?.persistent]));
  if (key === lastKey) return; lastKey = key;
  const near = list.scrollHeight - list.scrollTop - list.clientHeight < 80, keep = list.scrollTop;
  list.replaceChildren();
  let day = '';
  for (const m of msgs) {
    const d = fmtDay(m.ts); if (d !== day) { day = d; list.append(H('div', { class: 'day' }, d)); }
    const q = m.quote && byId[m.quote];
    const el = H('div', { class: 'm' + (m.kind === 'system' ? ' sys' : ''), id: 'm-' + m.id },
      avatar(m.from),
      H('div', { class: 'b' },
        H('div', { class: 'hd' }, H('span', { class: 'nm' }, m.from), m.tag ? H('span', { class: 'tag' }, m.tag) : null, H('span', { class: 'ts' }, fmtTime(m.ts)),
          S.me.read_only || m.kind === 'system' ? null : H('button', { class: 'link rep', type: 'button', onclick: () => setQuote(m.id) }, '↩ Antworten')),
        m.quote ? H('div', { class: 'q', onclick: () => { const t = document.getElementById('m-' + m.quote); if (t) { t.scrollIntoView({ block: 'center' }); t.classList.add('hl'); setTimeout(() => t.classList.remove('hl'), 1500); } } },
          q ? `${q.from}${q.tag ? ' [' + q.tag + ']' : ''}: ${q.body.split('\n')[0].slice(0, 120)}` : 'Nachricht (nicht mehr geladen)') : null,
        m.body ? renderBody(m.body) : null,
        m.file ? renderFile(m) : null,
        m.reactions?.length ? H('div', {}, m.reactions.map(([e, n]) => H('span', { class: 'rx' }, `${e} ${n}`))) : null));
    list.append(el);
  }
  for (const [id, p] of Object.entries(S.pend)) {
    if (p.chan !== S.cur) continue;
    if (msgs.some(m => m.id === id) || Date.now() - p.t > 180000) { delete S.pend[id]; continue; }
    list.append(H('div', { class: 'm pend' }, H('div', { class: 'b' }, `📎 ${p.name} wird geprüft …`)));
  }
  if (near || S.stick) list.scrollTop = list.scrollHeight; else list.scrollTop = keep;
}
// ---- modal dialogs (votes, proposals, channels): signed actions always go through a confirm step ----
function closeModal() { $('#modal').classList.add('hidden'); $('#mbox').replaceChildren(); }
function modal(title, kids, buttons) {
  const box = $('#mbox'); box.replaceChildren(H('h3', {}, title), ...kids, H('div', { class: 'mbtn' }, ...buttons));
  $('#modal').classList.remove('hidden');
  const f = box.querySelector('input,textarea,select'); if (f) f.focus();
}
const btn = (t, f, cls) => H('button', { type: 'button', class: cls || '', onclick: f }, t);
const cancelBtn = () => btn('Abbrechen', closeModal);
document.addEventListener('keydown', ev => { if (ev.key === 'Escape' && !$('#modal').classList.contains('hidden')) closeModal(); });
$('#modal').addEventListener('mousedown', ev => { if (ev.target === $('#modal')) closeModal(); });
const WARN = 'Echte Signatur, nicht rückgängig zu machen.';

function topicDialog() {
  const n = H('input', { maxlength: 64, placeholder: 'Name des Kanals (max. 64 Zeichen)' });
  const b = H('textarea', { rows: 3, placeholder: 'Erste Nachricht (legt den Kanal an)' });
  const err = H('p', { class: 'err' });
  const go = async () => {
    try { const r = await api('/api/topic', { name: n.value, body: b.value }); closeModal(); if (!S.extra.includes(r.key.slice(2))) S.extra.push(r.key.slice(2)); S.cur = r.key; S.view = 'chat'; S.stick = true; render(); toast('Kanal angelegt'); }
    catch (e) { err.textContent = e.message; }
  };
  modal('Neuer Kanal', [H('p', { class: 'hint' }, 'Ein Kanal entsteht mit der ersten Nachricht. Sie geht an alle Mitglieder (nur als Ablage, kein privater Raum).'), n, b, err], [cancelBtn(), btn('Anlegen und senden', go, 'pri')]);
}

function voteDialog(p, approve) {
  const note = H('textarea', { rows: 3, placeholder: 'Begründung (optional, erscheint im Vorschlagskanal)' });
  const err = H('p', { class: 'err' });
  const go = async () => {
    try { await api('/api/vote', { id: p.id, approve, note: note.value, confirm: true }); closeModal(); delete S.det[p.id]; toast(approve ? 'Zustimmung gesendet' : 'Ablehnung gesendet'); }
    catch (e) { err.textContent = e.message; }
  };
  modal(`#${p.id}: ${approve ? 'Zustimmen' : 'Ablehnen'}`, [H('p', { class: 'warn' }, WARN), H('p', {}, `${p.op}${p.summary ? ' ' + p.summary : ''} von ${p.by}`), note, err],
    [cancelBtn(), btn(approve ? 'Verbindlich zustimmen' : 'Verbindlich ablehnen', go, approve ? 'pri' : 'dng')]);
}

function withdrawDialog(p) {
  const note = H('textarea', { rows: 2, placeholder: 'Grund (optional)' });
  const err = H('p', { class: 'err' });
  const go = async () => {
    try { await api('/api/withdraw', { id: p.id, note: note.value, confirm: true }); closeModal(); delete S.det[p.id]; toast('Vorschlag zurückgezogen'); }
    catch (e) { err.textContent = e.message; }
  };
  modal(`#${p.id} zurückziehen`, [H('p', { class: 'warn' }, 'Zieht deinen offenen Vorschlag für alle zurück. Nicht rückgängig zu machen.'), note, err], [cancelBtn(), btn('Zurückziehen', go, 'dng')]);
}

function proposeDialog() {
  const kinds = S.me.kinds || [];
  const sel = H('select', {});
  const grp = (l, f) => { const g = H('optgroup', { label: l }); for (const k of kinds.filter(f)) g.append(H('option', { value: k.id }, k.label)); if (g.children.length) sel.append(g); };
  grp('Vorschlag', k => !k.advanced); grp('Erweitert', k => k.advanced);
  const fields = H('div', { class: 'fields' }), err = H('p', { class: 'err' });
  let a, b;
  const files = () => (S.s.msgs || []).filter(m => m.file && m.file.upload && !m.file.upload.persistent);
  const build = () => {
    const k = kinds.find(x => x.id === sel.value); fields.replaceChildren(); err.textContent = '';
    a = b = null;
    if (k.id === 'persist') {
      a = H('select', {}, ...files().map(m => H('option', { value: m.id }, `${m.file.name} (${fmtSize(m.file.size)}, von ${m.from})`)));
      if (!a.children.length) fields.append(H('p', { class: 'hint' }, 'Keine temporäre Datei im Chat.'));
      fields.append(H('label', {}, 'Datei', a));
    } else if (k.a) { a = H('input', { maxlength: 1000 }); fields.append(H('label', {}, k.a, a)); }
    if (k.b) { b = H('textarea', { rows: 10 }); fields.append(H('label', {}, k.b, b)); }
    if (k.advanced) fields.prepend(H('p', { class: 'warn' }, 'Erweitert: wirkt auf die ganze Republik (Netzwerk bzw. Charta-Funktionen). Nur mit Bedacht.'));
  };
  sel.addEventListener('change', build); build();
  const data = () => ({ kind: sel.value, a: a ? a.value : '', b: b ? b.value : '' });
  const next = async () => {
    try {
      const r = await api('/api/propose/preview', data());
      const send = async () => {
        try { const j = await api('/api/propose', { ...data(), confirm: true }); closeModal(); toast('Vorschlag eingereicht' + (j.id ? ` (#${j.id})` : '')); }
        catch (e) { err2.textContent = e.message; }
      };
      const err2 = H('p', { class: 'err' });
      modal('Vorschau: das wird gesendet', [H('p', { class: 'warn' }, 'Vorschlag einreichen = signierte Aktion. ' + WARN + ' (Zurückziehen geht nur, solange er offen ist.)'),
        H('pre', { class: 'pv' }, r.preview), H('details', {}, H('summary', {}, 'Technisch (MCP-Aufruf)'), H('pre', { class: 'pv' }, r.tool + ' ' + JSON.stringify(r.args, null, 1))), err2],
        [btn('Zurück', proposeDialog), btn('Verbindlich einreichen', send, 'pri')]);
    } catch (e) { err.textContent = e.message; }
  };
  modal('Vorschlag erstellen', [H('label', {}, 'Typ', sel), fields, err], [cancelBtn(), btn('Vorschau', next, 'pri')]);
}

// ---- proposals ----
S.det = {}; S.open = new Set();
const propKey = p => `${p.state}|${p.approvals}|${JSON.stringify(p.votes)}`;
async function loadDetail(p) {
  const k = propKey(p);
  if (S.det[p.id] && S.det[p.id].k === k) return;
  S.det[p.id] = { k, d: S.det[p.id]?.d, loading: true };
  try { const d = await api('/api/proposal/' + p.id); S.det[p.id] = { k, d }; } catch (e) { S.det[p.id] = { k, err: e.message }; }
  if (S.view === 'props') renderProps();
}
const VOTE_DE = { approved: 'zugestimmt', declined: 'abgelehnt', open: 'offen' };
function diffView(text) {
  const pre = H('pre', { class: 'diff' });
  for (const l of text.split('\n')) pre.append(H('span', { class: l.startsWith('+') && !l.startsWith('+++') ? 'add' : l.startsWith('-') && !l.startsWith('---') ? 'del' : l.startsWith('@@') ? 'hunk' : '' }, l + '\n'));
  return pre;
}
function detailView(p) {
  const e = S.det[p.id], box = H('div', { class: 'pdet' });
  if (!e || (e.loading && !e.d)) return H('div', { class: 'pdet votes' }, e && e.err ? 'Fehler: ' + e.err : 'lädt …');
  if (e.err) return H('div', { class: 'pdet votes' }, 'Fehler: ' + e.err);
  const d = e.d;
  box.append(H('div', { class: 'votes' }, `Art: ${d.surface} / ${d.op}${d.paths.length ? ' · Seiten: ' + d.paths.join(', ') : ''}${d.superseded ? ' · Basis geändert (' + d.superseded + ')' : ''}`));
  const me = S.s.seat;
  box.append(H('ul', { class: 'stances' }, ...d.votes.map(([m, v]) => H('li', { class: 'v-' + v }, `${m}${m === me ? ' (du)' : ''}: ${VOTE_DE[v] || v}`))));
  if (d.value) box.append(d.op === 'wiki_patch' ? diffView(d.value) : H('pre', { class: 'diff' }, d.value));
  else if (d.proposed || d.current) { if (d.current) box.append(H('div', { class: 'votes' }, 'Vorher:'), H('pre', { class: 'diff' }, d.current)); if (d.proposed) box.append(H('div', { class: 'votes' }, 'Nachher:'), H('pre', { class: 'diff' }, d.proposed)); }
  return box;
}
function renderProps() {
  const box = $('#props'); box.replaceChildren();
  const head = H('div', { class: 'phead' }, H('h2', {}, 'Vorschläge'));
  if (!S.me.read_only) head.append(btn('+ Vorschlag', proposeDialog, 'pri'));
  box.append(head);
  if (!S.s.props.length) box.append(H('p', { class: 'day' }, 'Keine Vorschläge'));
  for (const p of S.s.props) {
    const open = S.open.has(p.id), ro = S.me.read_only;
    const mine = (p.votes.find(v => v[0] === S.s.seat) || [])[1];
    const acts = H('div', { class: 'pact' },
      btn(open ? 'Details ▾' : 'Details ▸', () => { if (open) S.open.delete(p.id); else { S.open.add(p.id); loadDetail(p); } renderProps(); }, 'link'),
      H('a', { onclick: () => { S.cur = p.chan; S.view = 'chat'; render(); } }, 'Diskussion öffnen'));
    if (!ro && p.state === 'proposed') {
      acts.append(btn('Zustimmen', () => voteDialog(p, true), 'pri'), btn('Ablehnen', () => voteDialog(p, false), 'dng'));
      acts.lastChild.disabled = acts.lastChild.previousSibling.disabled = !p.todo;
      if (!p.todo) acts.lastChild.title = acts.lastChild.previousSibling.title = 'Du hast hier schon abgestimmt';
      if (p.can_withdraw) acts.append(btn('Zurückziehen', () => withdrawDialog(p)));
    }
    box.append(H('div', { class: 'prop' },
      H('h4', {}, `#${p.id} ${p.op}${p.summary ? ' ' + p.summary : ''}`, H('span', { class: 'st ' + p.state }, p.state)),
      H('div', { class: 'votes' }, `von ${p.by} · ${p.approvals}/${p.threshold} Zustimmungen · deine Stimme: ${mine ? (VOTE_DE[mine] || mine) : '–'}`),
      acts, open ? detailView(p) : null));
    if (open) loadDetail(p);
  }
}
function render() {
  if (!S.s || S.s.loading) return;
  if (!chanEntries().some(c => c.key === S.cur)) S.cur = 'g';
  renderSide();
  const props = S.view === 'props';
  $('#msgs').classList.toggle('hidden', props); $('#props').classList.toggle('hidden', !props); $('#composer').classList.toggle('hidden', props || S.me.read_only);
  $('#mhead').classList.toggle('hidden', props);
  if (props) renderProps(); else renderMsgs();
  const b = $('#banner'); b.classList.toggle('hidden', !S.s.err && !S.me.read_only);
  b.textContent = S.s.err ? 'moltd nicht erreichbar: ' + S.s.err : 'Nur-Lesen-Modus: Senden ist deaktiviert';
  b.style.background = S.s.err ? '' : 'var(--mut)';
  updateQuote();
}

// ---- composer ----
function setQuote(id) { S.quote = id; updateQuote(); $('#input').focus(); }
function updateQuote() {
  const q = S.quote && S.s.msgs.find(m => m.id === S.quote);
  if (S.quote && !q) S.quote = null;
  $('#quote').classList.toggle('hidden', !q);
  if (q) $('#qtext').textContent = `↩ ${q.from}${q.tag ? ' [' + q.tag + ']' : ''}: ${q.body.split('\n')[0].slice(0, 100)}`;
}
// ---- file upload: button, drag & drop, paste ----
const maxUp = () => S.me?.max_upload || 0;
function attach(f) {
  if (!f || S.me.read_only) return;
  if (maxUp() && f.size > maxUp()) return toast(`Datei zu groß (max. ${fmtSize(maxUp())})`, true);
  if (!f.size) return toast('Datei ist leer', true);
  S.att = f; updateChip(); $('#input').focus();
}
function updateChip() {
  $('#chip').classList.toggle('hidden', !S.att);
  if (S.att) { $('#chipname').textContent = S.att.name || 'Einfügung'; $('#chipsize').textContent = fmtSize(S.att.size); }
  $('#chipprog').classList.add('hidden');
}
function clearAtt() { if (S.xhr) { S.xhr.abort(); S.xhr = null; } S.att = null; S.sending = false; $('#sendbtn').disabled = false; $('#filein').value = ''; updateChip(); }
function upload() {
  if (S.sending) return;
  const f = S.att, ta = $('#input'), prog = $('#chipprog');
  const name = f.name || ('Einfügung.' + ((f.type || '').split('/')[1] || 'bin')), chan = S.cur;
  S.sending = true; $('#sendbtn').disabled = true; prog.value = 0; prog.classList.remove('hidden');
  const q = new URLSearchParams({ name, ch: chan, text: ta.value });
  const x = new XMLHttpRequest(); S.xhr = x;
  x.open('POST', '/api/upload?' + q);
  x.setRequestHeader('X-CSRF-Token', S.me.csrf); x.setRequestHeader('Content-Type', 'application/octet-stream');
  x.upload.onprogress = ev => { if (ev.lengthComputable) prog.value = ev.loaded * 100 / ev.total; };
  x.onload = () => {
    let j = {}; try { j = JSON.parse(x.responseText); } catch {}
    if (x.status === 401) { showLogin(); return; }
    if (x.status >= 200 && x.status < 300) {
      if (j.id) S.pend[j.id] = { name: j.name || name, chan, t: Date.now() };
      ta.value = ''; S.quote = null; S.stick = true; S.xhr = null; S.att = null; $('#filein').value = ''; updateChip();
      S.sending = false; $('#sendbtn').disabled = false; if (S.s) render();
    } else { toast('Upload fehlgeschlagen: ' + (j.error || 'HTTP ' + x.status), true); S.xhr = null; S.sending = false; $('#sendbtn').disabled = false; prog.classList.add('hidden'); }
  };
  x.onerror = () => { toast('Upload fehlgeschlagen: Verbindung', true); S.xhr = null; S.sending = false; $('#sendbtn').disabled = false; prog.classList.add('hidden'); };
  x.send(f);
}
$('#attach').addEventListener('click', () => $('#filein').click());
$('#filein').addEventListener('change', ev => attach(ev.target.files[0]));
$('#chipx').addEventListener('click', clearAtt);
$('#input').addEventListener('paste', ev => { const f = [...(ev.clipboardData?.files || [])][0]; if (f) { ev.preventDefault(); attach(f); } });
{
  let depth = 0; const main = document.querySelector('main'), hasFiles = ev => [...(ev.dataTransfer?.types || [])].includes('Files');
  main.addEventListener('dragenter', ev => { if (hasFiles(ev) && !S.me?.read_only) { depth++; $('#drop').classList.remove('hidden'); ev.preventDefault(); } });
  main.addEventListener('dragover', ev => { if (hasFiles(ev)) ev.preventDefault(); });
  main.addEventListener('dragleave', () => { if (--depth <= 0) { depth = 0; $('#drop').classList.add('hidden'); } });
  main.addEventListener('drop', ev => { if (!hasFiles(ev)) return; ev.preventDefault(); depth = 0; $('#drop').classList.add('hidden'); attach(ev.dataTransfer.files[0]); });
}
$('#qx').addEventListener('click', () => { S.quote = null; updateQuote(); });
async function send() {
  const ta = $('#input'), body = ta.value;
  if (S.att) return upload();
  if (!body.trim() || S.sending) return;
  S.sending = true; $('#sendbtn').disabled = true;
  try { await api('/api/send', { channel: chanObj(S.cur), body, quote: S.quote || undefined }); ta.value = ''; S.quote = null; S.stick = true; }
  catch (e) { toast('Senden fehlgeschlagen: ' + e.message, true); }
  S.sending = false; $('#sendbtn').disabled = false; ta.focus();
}
$('#composer').addEventListener('submit', ev => { ev.preventDefault(); send(); });
$('#input').addEventListener('keydown', ev => { if (ev.key === 'Enter' && !ev.shiftKey && !ev.isComposing && ev.keyCode !== 229) { ev.preventDefault(); send(); } });
$('#newtopic').addEventListener('click', () => { if (!S.me.read_only) topicDialog(); else toast('Nur-Lesen-Modus', true); });
async function markRead() { try { await api('/api/mark_read', { channel: chanObj(S.cur) }); } catch (e) { toast('Fehler: ' + e.message, true); } }
$('#markread').addEventListener('click', markRead);
$('#menu').addEventListener('click', () => $('#side').classList.toggle('open'));
document.querySelectorAll('#tabs button').forEach(b => b.addEventListener('click', () => { S.view = b.dataset.view; render(); }));

// ---- notifications ----
const mode = () => store.get('molt.notify', 'mentions');
function relevant(m, s) {
  const mode_ = mode(); if (mode_ === 'off' || m.from === s.seat || m.kind === 'system') return false;
  if (mode_ === 'all') return true;
  const me = S.me.tag.toLowerCase(), b = m.body.toLowerCase();
  if (b.includes('@' + me) || b.includes('@' + s.seat.toLowerCase())) return true;
  const q = m.quote && s.msgs.find(x => x.id === m.quote);
  return !!(q && q.tag === S.me.tag);
}
function notify(title, body) {
  if (typeof Notification === 'undefined' || Notification.permission !== 'granted') return;
  if (document.visibilityState === 'visible' && document.hasFocus()) return;
  try { new Notification(title, { body: body.slice(0, 160), icon: '/icon.svg', tag: title + body.slice(0, 20) }); } catch {}
}
function checkNew(s) {
  const first = !S.seen; S.seen = S.seen || new Set();
  for (const m of s.msgs) {
    if (S.seen.has(m.id)) continue; S.seen.add(m.id);
    if (!first && relevant(m, s)) notify(`${m.from}${m.tag ? ' [' + m.tag + ']' : ''} · ${(s.chans.find(c => c.key === m.chan) || {}).label || ''}`, m.body || (m.file ? m.file.name : ''));
  }
  if (!first && s.todo > S.todo && mode() !== 'off') notify(s.name || 'Molt', 'Neue Abstimmung offen');
  S.todo = s.todo;
}
$('#notify').value = mode();
$('#notify').addEventListener('change', async ev => { store.set('molt.notify', ev.target.value); if (ev.target.value !== 'off' && typeof Notification !== 'undefined' && Notification.permission === 'default') await Notification.requestPermission(); });
$('#automark').checked = store.get('molt.automark', '0') === '1';
$('#automark').addEventListener('change', ev => store.set('molt.automark', ev.target.checked ? '1' : '0'));

// ---- live state ----
function connect() {
  if (S.es) S.es.close();
  const es = new EventSource('/api/events'); S.es = es;
  es.addEventListener('state', ev => {
    let s; try { s = JSON.parse(ev.data); } catch { return; }
    S.retry = 0;
    if (s.loading) return;
    S.s = s; checkNew(s); render();
    const ent = s.chans.find(c => c.key === S.cur);
    if (S.stick && !$('#msgs').classList.contains('hidden')) { $('#msgs').scrollTop = $('#msgs').scrollHeight; S.stick = false; }
    if ($('#automark').checked && !S.me.read_only && ent?.unread && document.visibilityState === 'visible') { clearTimeout(S.am); S.am = setTimeout(markRead, 1500); }
  });
  es.onerror = () => { es.close(); if (S.es === es) S.es = null; reconnect(); };
}
// exponential backoff 1s .. 30s; a 401 from /api/me (logged out / expired) shows the login instead of retrying
function reconnect() {
  const wait = Math.min(30000, 1000 * 2 ** S.retry++);
  setTimeout(() => api('/api/me').then(() => { if (!S.es) connect(); }).catch(e => { if (e.message !== 'nicht angemeldet') reconnect(); }), wait);
}
function start() {
  $('#login').classList.add('hidden'); $('#app').classList.remove('hidden');
  $('#who').textContent = S.me.user;
  connect();
}
(async () => {
  try { S.me = await api('/api/me'); start(); }
  catch { try { const r = await fetch('/api/me'); } catch {} showLogin(); }
  // multi-user installs need the name field; single-user ones don't: always offer it, optional
  $('#lu').classList.remove('hidden');
})();
