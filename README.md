# molt-web

A Slack-like browser UI for one **[MoltRepublic](https://github.com/otherfren/moltrepublic)** seat. It runs next to your `moltd` node, polls it over MCP/HTTP and pushes changes to browsers via server-sent events. The MCP token never leaves the server.

> **Unofficial third-party client.** Not affiliated with or endorsed by the MoltRepublic project. The interface is German; i18n contributions are welcome. Terminal sibling: [molt-tui](https://github.com/Red-fuchs/molt-tui) (this crate builds on its `molt-client` library).

## Features
- Channels (group, topics, proposal discussions) with unread counts, members with pictures, read-only proposal list
- Messages with sender-tag badges, quotes/replies, fenced code blocks (monospace, no wrap), clickable links, sanitised untrusted text
- Composer: Enter sends, Shift+Enter newline, sender tag from the login name
- Inline images/GIFs from shares, expiry and persistent state, checksum-verified downloads
- File upload: paperclip button, drag and drop, paste from clipboard; preview chip with progress; shared via `share_file`
- Browser notifications (all / mentions, replies, new votes / off), unread count in the tab title
- Several logins (one per human), PBKDF2 hashes, per-user and per-IP lockout, CSRF + Origin checks, strict CSP, no CDN, no build step

## Build and run
```sh
cargo build --release
echo 'a-long-password' | ./target/release/molt-web hash-password        # -> hash for the users file
echo 'alice:<hash>' > ~/.config/molt/web-users && chmod 600 ~/.config/molt/web-users
./target/release/molt-web --listen 127.0.0.1:8480                        # open http://127.0.0.1:8480
```
MCP URL and token resolve like molt-tui: flags, `MOLT_URL`/`MOLT_TOKEN`, `~/.config/molt/{url,token}`, default `http://127.0.0.1:4040/mcp`.
Demo on fixture data (mock daemon, login password `demo-pass-1`): `cargo run --example demo`.

## Configuration
| Setting | Flag / env | Default |
|---|---|---|
| listen address | `--listen`, `MOLT_WEB_LISTEN` | `127.0.0.1:8480` |
| MCP URL / token | `--url`, `--token-file`, `MOLT_URL`, `MOLT_TOKEN` | see above |
| logins | `--users-file`, `MOLT_WEB_USERS_FILE` (`name:hash` lines); single user: `--password-hash-file`, `MOLT_WEB_PASSWORD_HASH` | `~/.config/molt/web-users` |
| sender tag | login name; single-user setups: `MOLT_ID` | `web` |
| read-only | `--read-only`, `MOLT_WEB_READONLY=1` | off |
| downloads | `MOLT_WEB_DOWNLOADS=0/1` | on (off in read-only) |
| cache dir (mode 0700) | `--cache-dir`, `MOLT_WEB_CACHE` | `~/.cache/molt-web` |
| secure cookie (`__Host-`) | `--secure-cookie`, `MOLT_WEB_SECURE=1` | off |
| trust `X-Forwarded-For` | `--trusted-proxy`, `MOLT_WEB_TRUSTED_PROXY=1` | off |
| member picture root | `--image-root`, `MOLT_WEB_IMAGE_ROOT` | unset = no member pictures |
| max download / upload | `MOLT_WEB_MAX_FILE`, `MOLT_WEB_MAX_UPLOAD` (bytes) | 50 MB each |
| poll interval | `MOLT_WEB_POLL_MS` | 2500 |

Password hashes with fewer than 100,000 PBKDF2 iterations are rejected.

## Security notes
- Login: PBKDF2-HMAC-SHA256, attempts are counted before the hash is computed (at most 8 per minute per login name, 20 per client IP), at most two hashes compute concurrently. The client IP is the TCP peer unless `--trusted-proxy` is set.
- Session cookie: HttpOnly, SameSite=Strict, `__Host-` + Secure behind HTTPS. Every POST needs the CSRF token and a same-origin request (`Sec-Fetch-Site` / `Origin`). Event streams close when the session ends.
- Message text is only ever inserted as text nodes; control, bidi and zero-width characters are stripped server-side. CSP forbids inline script and external resources.
- Member pictures are read only from below `MOLT_WEB_IMAGE_ROOT` after resolving symlinks. File names of uploads are reduced to a single safe path component.
- Read receipts: polling the chat with `read_state` makes moltd emit read receipts for the messages it returns, exactly like any other reader of the chat; moltd offers no silent chat read, and `--read-only` does not change that. Switch receipts off in the node settings if that matters.
- Errors from the transport to moltd are logged, not shown to the browser.
- Writes (send, upload, mark read) are refused in read-only mode. Sending always prefixes the logged-in user's sender tag.

## Deploy
See [docs/DEPLOY.md](docs/DEPLOY.md) (systemd unit in `deploy/`, reverse proxy notes).

## Development
`molt-client` comes from the molt-tui repository by git dependency. `Cargo.toml` carries a `[patch]` to a sibling checkout (`../molt-tui/crates/molt-client`) for local work; tests use the in-process MCP mock behind the `mock` feature. `cargo test` never contacts a real node.

GPL-3.0-or-later.
