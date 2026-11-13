# Deploying molt-web

molt-web talks to `moltd` over MCP/HTTP and serves the browser UI. It must reach the MCP endpoint (token required) and should run on the same host or a private link.

## 1. Build
- `cargo build --release` (Rust 2024 edition, stable >= 1.88), or `scripts/build-linux.sh` for a linux x86_64 binary via docker.
- The binary has no runtime dependencies besides libc; the frontend is embedded.

## 2. Install (systemd, dedicated user)
```sh
sudo useradd --system --create-home --shell /usr/sbin/nologin molt
sudo -u molt install -d -m700 /home/molt/molt-web /home/molt/.config/molt
sudo -u molt install -m755 target/release/molt-web /home/molt/molt-web/
sudo -u molt install -m600 /path/to/mcp-token /home/molt/.config/molt/token      # same token moltd's MCP expects
read -rs PW; echo "$PW" | sudo -u molt /home/molt/molt-web/molt-web hash-password   # prints name-less hash
echo 'alice:<hash>' | sudo -u molt tee /home/molt/.config/molt/web-users          # one line per human: login name = sender tag
sudo cp deploy/molt-web.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now molt-web
```
`%h` in the unit expands to the home of `User=`. Adjust `MOLT_URL`, `--listen` and `MOLT_WEB_IMAGE_ROOT` (the directory where moltd keeps member pictures; leave it unset to disable member pictures) to your node. Try `--read-only` first.

## 3. Expose it
Do not bind a non-loopback address without TLS. Put a reverse proxy with HTTPS in front, proxy to the loopback listener, forward `Host` unchanged (the Origin check compares it), and start molt-web with `--secure-cookie` (session cookie becomes `__Host-` prefixed + `Secure`) and, if the proxy sets `X-Forwarded-For`, `--trusted-proxy` so login limits apply per real client IP. Only use `--trusted-proxy` when every request really passes through your proxy.

## Files
- Downloads (`download_file`) land in the cache dir as `<message id>`; they are served only after size and sha256 match the share. Previews are limited to png/jpeg/gif/webp by magic bytes.
- Uploads go to `<cache>/uploads/<random>/<name>` (dirs 0700, files 0600) and are shared with `share_file`. moltd serves the bytes peer-to-peer from that path, so the file must stay while the share lives. A background pass (every 10 min) removes downloads and uploads older than the chat retention (+1 day for uploads) and keeps everything whose share is persistent.
- The cache dir must be readable/writable by the user moltd runs as (same user is simplest).

## Operations
- Logs: `journalctl -u molt-web -f`. Restarting molt-web never touches moltd. Sessions are in memory; everyone logs in again after a restart.
- SIGTERM/SIGINT close open event streams and exit.
- Polling `read_state` makes moltd send read receipts for the messages it returns (same as any chat read), unless the node has receipts switched off. There is no silent chat read in the MCP tool set. `mark_channel_read` (button / opt-in auto mark) only moves the private cursor.
