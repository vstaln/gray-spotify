//! gray-spotify — Spotify playback control via the Web API.
//!
//! Port of hermes' spotify plugin (single-tool subset): one `spotify` tool
//! {action: play|pause|next|prev|queue|search|now|volume} plus `/spotify auth`
//! which runs the OAuth PKCE flow: prints the authorize URL, asks for the
//! pasted code via `host/ask` (with `/spotify code <code>` as a fallback),
//! exchanges it via curl, and stores tokens in `~/.gray/spotify/token.json`.
//! On a 401 the refresh token is used once and the call retried.
//!
//! HTTP is shelled out to `curl`; the app client id comes from
//! `SPOTIFY_CLIENT_ID` (never hardcoded).

use std::collections::HashMap;
use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use serde_json::{Value, json};

const API_BASE: &str = "https://api.spotify.com/v1";
const ACCOUNTS_BASE: &str = "https://accounts.spotify.com";
const DEFAULT_REDIRECT_URI: &str = "http://127.0.0.1:43827/spotify/callback";
const SCOPE: &str = "user-modify-playback-state user-read-playback-state user-read-currently-playing user-read-recently-played playlist-read-private playlist-read-collaborative playlist-modify-public playlist-modify-private user-library-read user-library-modify";
const ASK_TTL: Duration = Duration::from_secs(300);

fn manifest() -> Value {
    json!({
        "name": "spotify",
        "version": env!("CARGO_PKG_VERSION"),
        "protocol": "1.1",
        "capabilities": ["host.ask", "host.say"],
        "tools": [{
            "name": "spotify",
            "description": "Control Spotify playback. Actions: play (optional uri or query), pause, next, prev, queue (uri or query), search (query → top 5 tracks), now (what's playing), volume (percent 0-100). Requires a one-time `/spotify auth` and SPOTIFY_CLIENT_ID in the environment.",
            "parameters": {
                "type": "object",
                "properties": {
                    "action":  {"type": "string", "enum": ["play", "pause", "next", "prev", "queue", "search", "now", "volume"]},
                    "query":   {"type": "string", "description": "Search text (search; also play/queue resolve the top hit)"},
                    "uri":     {"type": "string", "description": "spotify:track:… / spotify:album:… / spotify:playlist:… uri"},
                    "percent": {"type": "integer", "description": "Volume 0-100 for action=volume"}
                },
                "required": ["action"]
            }
        }],
        "commands": ["/spotify"],
    })
}

// ---------- tiny crypto/encoding helpers (no extra crates) ------------------

fn sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];
    let mut msg = data.to_vec();
    let bitlen = (data.len() as u64) * 8;
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bitlen.to_be_bytes());
    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([chunk[4 * i], chunk[4 * i + 1], chunk[4 * i + 2], chunk[4 * i + 3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g; g = f; f = e; e = d.wrapping_add(t1);
            d = c; c = b; b = a; a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a); h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c); h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e); h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g); h[7] = h[7].wrapping_add(hh);
    }
    let mut out = [0u8; 32];
    for i in 0..8 {
        out[4 * i..4 * i + 4].copy_from_slice(&h[i].to_be_bytes());
    }
    out
}

const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64_encode(bytes: &[u8], url_safe: bool) -> String {
    let mut out = String::with_capacity(bytes.len() * 4 / 3 + 4);
    for chunk in bytes.chunks(3) {
        let n = chunk.iter().fold(0u32, |acc, &b| (acc << 8) | b as u32) << (8 * (3 - chunk.len()));
        let mut idx = [
            (n >> 18) & 63,
            (n >> 12) & 63,
            (n >> 6) & 63,
            n & 63,
        ];
        for i in 1..4 {
            if i > chunk.len() {
                idx[i] = 64; // padding marker
            }
        }
        for &ix in idx.iter() {
            if ix == 64 {
                out.push('=');
            } else {
                let c = B64[ix as usize] as char;
                let c = if url_safe { match c { '+' => '-', '/' => '_', c => c } } else { c };
                out.push(c);
            }
        }
    }
    out
}

fn urlencode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            b => format!("%{b:02X}"),
        })
        .collect()
}

fn rand_bytes(n: usize) -> Vec<u8> {
    std::fs::read("/dev/urandom")
        .map(|b| b.into_iter().take(n).collect())
        .unwrap_or_else(|_| {
            let t = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default();
            (0..n).map(|i| ((t.subsec_nanos() >> (i % 24)) as u8) ^ (i as u8)).collect()
        })
}

// ---------- state -----------------------------------------------------------

fn state_dir() -> PathBuf {
    let home = std::env::var_os("GRAY_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".gray")))
        .unwrap_or_else(|| PathBuf::from("."));
    home.join("spotify")
}

fn token_path() -> PathBuf {
    state_dir().join("token.json")
}

fn pkce_path() -> PathBuf {
    state_dir().join("pkce.json")
}

fn load_token() -> Result<Value, String> {
    let text = std::fs::read_to_string(token_path())
        .map_err(|_| "not authorized with Spotify — run /spotify auth (needs SPOTIFY_CLIENT_ID)".to_string())?;
    serde_json::from_str(&text).map_err(|e| format!("corrupt token file: {e}"))
}

fn save_token(t: &Value) -> Result<(), String> {
    let dir = state_dir();
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    std::fs::write(token_path(), serde_json::to_string_pretty(t).unwrap())
        .map_err(|e| format!("couldn't save token: {e}"))
}

// ---------- curl ------------------------------------------------------------

/// Run curl, return (http_status, body).
fn curl(args: &[String]) -> Result<(u16, String), String> {
    let out = std::process::Command::new("curl")
        .args(["-sS", "--max-time", "25", "-w", "\n%{http_code}"])
        .args(args)
        .output()
        .map_err(|e| format!("couldn't run curl: {e}"))?;
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    let (body, status) = text.rsplit_once('\n').unwrap_or((&text, "0"));
    let status: u16 = status.trim().parse().unwrap_or(0);
    if status == 0 && !out.status.success() {
        return Err(format!("curl failed: {}", String::from_utf8_lossy(&out.stderr).trim()));
    }
    Ok((status, body.to_string()))
}

fn api(method: &str, path: &str, query: &[(&str, String)], body: Option<Value>) -> Result<(u16, Value), String> {
    api_inner(method, path, query, body, true)
}

fn api_inner(
    method: &str,
    path: &str,
    query: &[(&str, String)],
    body: Option<Value>,
    retry: bool,
) -> Result<(u16, Value), String> {
    let token = load_token()?;
    let access = token.get("access_token").and_then(Value::as_str).unwrap_or("");
    let mut url = format!("{API_BASE}{path}");
    if !query.is_empty() {
        let qs: Vec<String> = query.iter().map(|(k, v)| format!("{k}={v}")).collect();
        url.push('?');
        url.push_str(&qs.join("&"));
    }
    let mut args = vec![
        "-X".into(), method.into(),
        "-H".into(), format!("Authorization: Bearer {access}"),
        "-H".into(), "Content-Type: application/json".into(),
        url,
    ];
    if let Some(b) = &body {
        args.push("-d".into());
        args.push(b.to_string());
    } else if method != "GET" {
        args.push("-d".into());
        args.push("{}".into());
    }
    let (status, text) = curl(&args)?;
    if status == 401 && retry {
        refresh_token(&token)?;
        return api_inner(method, path, query, body, false);
    }
    let v: Value = serde_json::from_str(&text).unwrap_or(json!({}));
    Ok((status, v))
}

fn api_ok(method: &str, path: &str, query: &[(&str, String)], body: Option<Value>) -> Result<Value, String> {
    let (status, v) = api(method, path, query, body)?;
    if (200..300).contains(&status) {
        return Ok(v);
    }
    let detail = v
        .pointer("/error/message")
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| {
            let t = v.to_string();
            if t == "{}" { String::new() } else { t.chars().take(200).collect() }
        });
    let hint = match status {
        404 => " (no active device? open Spotify on a device first)",
        403 => " (needs Premium / an active device)",
        _ => "",
    };
    Err(format!("spotify {method} {path} → {status}{hint}: {detail}"))
}

fn refresh_token(token: &Value) -> Result<(), String> {
    let refresh = token
        .get("refresh_token")
        .and_then(Value::as_str)
        .ok_or("token expired and no refresh_token stored — run /spotify auth again")?;
    let client_id = token.get("client_id").and_then(Value::as_str).unwrap_or("").to_string();
    let form = format!(
        "grant_type=refresh_token&refresh_token={}&client_id={}",
        urlencode(refresh),
        urlencode(&client_id)
    );
    let (status, text) = curl(&[
        "-X".into(), "POST".into(),
        "-H".into(), "Content-Type: application/x-www-form-urlencoded".into(),
        "-d".into(), form,
        format!("{ACCOUNTS_BASE}/api/token"),
    ])?;
    let v: Value = serde_json::from_str(&text).unwrap_or(json!({}));
    if status != 200 || v.get("access_token").is_none() {
        return Err(format!("token refresh failed ({status}) — run /spotify auth again"));
    }
    let mut t = token.clone();
    t["access_token"] = v["access_token"].clone();
    if let Some(rt) = v.get("refresh_token") {
        t["refresh_token"] = rt.clone();
    }
    let expires_in = v.get("expires_in").and_then(Value::as_u64).unwrap_or(3600);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    t["expires_at"] = json!(now + expires_in);
    save_token(&t)
}

// ---------- tool actions ----------------------------------------------------

fn fmt_track(t: &Value) -> String {
    let name = t.get("name").and_then(Value::as_str).unwrap_or("?");
    let artists = t
        .get("artists")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|x| x.get("name").and_then(Value::as_str))
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default();
    let album = t.pointer("/album/name").and_then(Value::as_str).unwrap_or("");
    let uri = t.get("uri").and_then(Value::as_str).unwrap_or("");
    format!("{name} — {artists} [{album}] ({uri})")
}

fn search_track(query: &str) -> Result<Value, String> {
    let v = api_ok("GET", "/search", &[("q", urlencode(query)), ("type", "track".into()), ("limit", "5".into())], None)?;
    Ok(v)
}

fn top_track_uri(query: &str) -> Result<String, String> {
    let v = search_track(query)?;
    v.pointer("/tracks/items/0/uri")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| format!("no tracks found for {query:?}"))
}

fn call_tool(name: &str, args: &Value) -> Result<String, String> {
    if name != "spotify" {
        return Err(format!("unknown tool: {name}"));
    }
    let action = args.get("action").and_then(Value::as_str).unwrap_or("");
    match action {
        "play" => {
            let mut body = json!({});
            if let Some(uri) = args.get("uri").and_then(Value::as_str).filter(|s| !s.is_empty()) {
                if uri.contains(":track:") {
                    body = json!({"uris": [uri]});
                } else {
                    body = json!({"context_uri": uri});
                }
            } else if let Some(q) = args.get("query").and_then(Value::as_str).filter(|s| !s.is_empty()) {
                let uri = top_track_uri(q)?;
                body = json!({"uris": [uri]});
            }
            api_ok("PUT", "/me/player/play", &[], Some(body))?;
            Ok("playing".into())
        }
        "pause" => {
            api_ok("PUT", "/me/player/pause", &[], None)?;
            Ok("paused".into())
        }
        "next" => {
            api_ok("POST", "/me/player/next", &[], None)?;
            Ok("skipped to next track".into())
        }
        "prev" => {
            api_ok("POST", "/me/player/previous", &[], None)?;
            Ok("back to previous track".into())
        }
        "queue" => {
            let uri = match args.get("uri").and_then(Value::as_str).filter(|s| !s.is_empty()) {
                Some(u) => u.to_string(),
                None => {
                    let q = args.get("query").and_then(Value::as_str).unwrap_or("");
                    if q.is_empty() {
                        return Err("queue needs uri or query".into());
                    }
                    top_track_uri(q)?
                }
            };
            api_ok("POST", "/me/player/queue", &[("uri", urlencode(&uri))], None)?;
            Ok(format!("queued {uri}"))
        }
        "search" => {
            let q = args.get("query").and_then(Value::as_str).unwrap_or("").trim();
            if q.is_empty() {
                return Err("search needs a query".into());
            }
            let v = search_track(q)?;
            let items = v.pointer("/tracks/items").and_then(Value::as_array).cloned().unwrap_or_default();
            if items.is_empty() {
                return Ok(format!("no tracks found for {q:?}"));
            }
            let lines: Vec<String> = items.iter().map(fmt_track).collect();
            Ok(lines.join("\n"))
        }
        "now" => {
            let (status, v) = api("GET", "/me/player/currently-playing", &[], None)?;
            if status == 204 {
                return Ok("nothing playing — start playback in Spotify first".into());
            }
            if !(200..300).contains(&status) {
                let detail = v.pointer("/error/message").and_then(Value::as_str).unwrap_or("");
                return Err(format!("spotify now → {status}: {detail}"));
            }
            let item = v.get("item").cloned().unwrap_or(json!({}));
            if item.is_null() || item.get("name").is_none() {
                return Ok("nothing playing".into());
            }
            let playing = v.get("is_playing").and_then(Value::as_bool).unwrap_or(false);
            Ok(format!("{} {}", if playing { "▶" } else { "⏸" }, fmt_track(&item)))
        }
        "volume" => {
            let pct = args
                .get("percent")
                .and_then(Value::as_i64)
                .ok_or("volume needs percent (0-100)")?
                .clamp(0, 100);
            api_ok("PUT", "/me/player/volume", &[("volume_percent", pct.to_string())], None)?;
            Ok(format!("volume {pct}%"))
        }
        other => Err(format!(
            "unknown action '{other}' — play|pause|next|prev|queue|search|now|volume"
        )),
    }
}

// ---------- auth (PKCE) -----------------------------------------------------

fn client_id() -> Result<String, String> {
    std::env::var("SPOTIFY_CLIENT_ID")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            "SPOTIFY_CLIENT_ID is not set — create an app at https://developer.spotify.com/dashboard, \
             add the redirect URI below, and export SPOTIFY_CLIENT_ID".to_string()
        })
}

fn redirect_uri() -> String {
    std::env::var("SPOTIFY_REDIRECT_URI")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_REDIRECT_URI.into())
}

/// Pull a `code` out of whatever the user pasted: bare code or full redirect URL.
fn extract_code(text: &str) -> Option<String> {
    let t = text.trim();
    if t.is_empty() {
        return None;
    }
    if let Some(pos) = t.find("code=") {
        let rest = &t[pos + 5..];
        let end = rest.find('&').unwrap_or(rest.len());
        let code = &rest[..end];
        if !code.is_empty() {
            return Some(code.to_string());
        }
    }
    if !t.contains(' ') && !t.contains('\n') && t.chars().all(|c| c.is_ascii_graphic()) {
        return Some(t.to_string());
    }
    None
}

fn exchange_code(code: &str) -> Result<String, String> {
    let pkce_text = std::fs::read_to_string(pkce_path())
        .map_err(|_| "no pending auth flow — run /spotify auth first".to_string())?;
    let pkce: Value = serde_json::from_str(&pkce_text).map_err(|e| format!("corrupt pkce state: {e}"))?;
    let client_id = pkce.get("client_id").and_then(Value::as_str).unwrap_or("");
    let verifier = pkce.get("code_verifier").and_then(Value::as_str).unwrap_or("");
    let redirect = pkce.get("redirect_uri").and_then(Value::as_str).unwrap_or("");
    let form = format!(
        "client_id={}&grant_type=authorization_code&code={}&redirect_uri={}&code_verifier={}",
        urlencode(client_id),
        urlencode(code),
        urlencode(redirect),
        urlencode(verifier),
    );
    let (status, text) = curl(&[
        "-X".into(), "POST".into(),
        "-H".into(), "Content-Type: application/x-www-form-urlencoded".into(),
        "-d".into(), form,
        format!("{ACCOUNTS_BASE}/api/token"),
    ])?;
    let v: Value = serde_json::from_str(&text).unwrap_or(json!({}));
    let access = v.get("access_token").and_then(Value::as_str).unwrap_or("");
    if status != 200 || access.is_empty() {
        let detail = v.pointer("/error_description")
            .or_else(|| v.pointer("/error/message"))
            .and_then(Value::as_str)
            .unwrap_or(&text);
        return Err(format!("token exchange failed ({status}): {detail}"));
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let token = json!({
        "client_id": client_id,
        "redirect_uri": redirect,
        "access_token": access,
        "refresh_token": v.get("refresh_token").and_then(Value::as_str).unwrap_or(""),
        "scope": v.get("scope").and_then(Value::as_str).unwrap_or(SCOPE),
        "expires_at": now + v.get("expires_in").and_then(Value::as_u64).unwrap_or(3600),
        "auth_type": "oauth_pkce",
    });
    save_token(&token)?;
    let _ = std::fs::remove_file(pkce_path());
    Ok("spotify authorized — tokens saved to ~/.gray/spotify/token.json".into())
}

type Pending = Arc<Mutex<HashMap<String, mpsc::Sender<Value>>>>;

fn next_id(counter: &Arc<Mutex<u64>>) -> String {
    let mut n = counter.lock().expect("counter");
    *n += 1;
    format!("q{n}")
}

fn host_send(out: &Arc<Mutex<std::io::Stdout>>, method: &str, params: Value, id: Option<&str>) {
    let req = match id {
        Some(id) => json!({"id": id, "method": method, "params": params}),
        None => json!({"method": method, "params": params}),
    };
    let mut o = out.lock().expect("stdout");
    let _ = writeln!(o, "{req}");
    let _ = o.flush();
}

fn host_ask(
    out: &Arc<Mutex<std::io::Stdout>>,
    pending: &Pending,
    counter: &Arc<Mutex<u64>>,
    question: &str,
) -> Result<String, String> {
    let id = next_id(counter);
    let (tx, rx) = mpsc::channel();
    pending.lock().expect("pending").insert(id.clone(), tx);
    host_send(
        out,
        "host/ask",
        json!({
            "questions": [{
                "id": "code",
                "header": "Spotify auth",
                "question": question,
                "options": [{"label": "Paste the `code` param or the full redirect URL", "description": "Choose Other / type the code as a note."}],
                "is_other": true
            }],
            "blocking": true
        }),
        Some(&id),
    );
    let res = rx.recv_timeout(ASK_TTL);
    pending.lock().expect("pending").remove(&id);
    match res {
        Err(_) => Err("no answer — paste the code with /spotify code <code-or-redirect-url> instead".into()),
        Ok(result) => {
            if let Some(err) = result.pointer("/error/message").and_then(Value::as_str)
                .or_else(|| result.get("error").and_then(|e| e.as_str()))
            {
                return Err(format!("host/ask failed: {err} — finish with /spotify code <code>"));
            }
            let entry = &result["answers"]["code"]["answers"];
            let answers: Vec<String> = entry
                .as_array()
                .map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect())
                .unwrap_or_default();
            for a in &answers {
                let a = a.strip_prefix("user_note: ").unwrap_or(a);
                if a == "Paste the `code` param or the full redirect URL" {
                    continue;
                }
                if let Some(code) = extract_code(a) {
                    return Ok(code);
                }
            }
            Err("empty answer — finish with /spotify code <code-or-redirect-url>".into())
        }
    }
}

fn run_command(
    argv: &[&str],
    out: &Arc<Mutex<std::io::Stdout>>,
    pending: &Pending,
    counter: &Arc<Mutex<u64>>,
) -> String {
    match argv.first().copied() {
        Some("auth") => {
            let client_id = match client_id() {
                Ok(c) => c,
                Err(e) => return e,
            };
            let redirect = redirect_uri();
            let verifier = b64_encode(&rand_bytes(64), true).trim_end_matches('=').chars().take(96).collect::<String>();
            let challenge = b64_encode(&sha256(verifier.as_bytes()), true).trim_end_matches('=').to_string();
            let state = rand_bytes(12).iter().map(|b| format!("{b:02x}")).collect::<String>();
            let url = format!(
                "{ACCOUNTS_BASE}/authorize?client_id={}&response_type=code&redirect_uri={}&scope={}&state={}&code_challenge_method=S256&code_challenge={}",
                urlencode(&client_id),
                urlencode(&redirect),
                urlencode(SCOPE),
                state,
                challenge,
            );
            let pkce = json!({
                "client_id": client_id,
                "redirect_uri": redirect,
                "code_verifier": verifier,
                "state": state,
            });
            let dir = state_dir();
            let _ = std::fs::create_dir_all(&dir);
            if std::fs::write(pkce_path(), pkce.to_string()).is_err() {
                return "couldn't save pkce state under ~/.gray/spotify/".into();
            }
            // Best-effort: surface the URL in chat too when host.say is granted.
            host_send(out, "host/say", json!({"text": format!("Spotify auth — open:\n{url}")}), Some(&next_id(counter)));
            let prompt = format!(
                "Open this URL, approve, and paste the `code` param (or the whole redirect URL):\n\n{url}\n\n\
                 (No browser callback is run — copy the code= value from the address bar after redirect.)"
            );
            match host_ask(out, pending, counter, &prompt) {
                Ok(code) => exchange_code(&code).unwrap_or_else(|e| e),
                Err(e) => format!(
                    "authorize URL:\n{url}\n\n{e}"
                ),
            }
        }
        Some("code") => {
            let pasted = argv[1..].join(" ");
            match extract_code(&pasted) {
                Some(code) => exchange_code(&code).unwrap_or_else(|e| e),
                None => "usage: /spotify code <code-or-redirect-url>".into(),
            }
        }
        Some("status") | None => {
            let cid = client_id().unwrap_or_else(|_| "(unset)".into());
            match load_token() {
                Ok(t) => {
                    let exp = t.get("expires_at").and_then(Value::as_u64).unwrap_or(0);
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    let ttl = exp.saturating_sub(now);
                    format!(
                        "gray-spotify {} — authorized (token refreshes via refresh_token; access token ttl {ttl}s). client_id env: {cid}",
                        env!("CARGO_PKG_VERSION")
                    )
                }
                Err(_) => format!(
                    "gray-spotify {} — not authorized. Run /spotify auth (client_id env: {cid})",
                    env!("CARGO_PKG_VERSION")
                ),
            }
        }
        Some("logout") => {
            let _ = std::fs::remove_file(token_path());
            let _ = std::fs::remove_file(pkce_path());
            "logged out — token deleted".into()
        }
        Some(other) => format!("unknown /spotify arg '{other}' — auth|code <code>|status|logout"),
    }
}

// ---------- wire loop -------------------------------------------------------

fn handle(
    req: &Value,
    out: &Arc<Mutex<std::io::Stdout>>,
    pending: &Pending,
    counter: &Arc<Mutex<u64>>,
) -> (Option<Value>, bool) {
    let id = req.get("id").cloned();
    let method = req.get("method").and_then(Value::as_str).unwrap_or("");
    let params = req.get("params").cloned().unwrap_or(Value::Null);
    let Some(id) = id else {
        return (None, method == "plugin/shutdown");
    };
    let result = match method {
        "plugin/manifest" => manifest(),
        "tool/call" => {
            let name = params.get("name").and_then(Value::as_str).unwrap_or("");
            let args = params.get("args").cloned().unwrap_or(Value::Null);
            match call_tool(name, &args) {
                Ok(text) => json!({ "content": text }),
                Err(e) => json!({ "content": e, "is_error": true }),
            }
        }
        "command/run" => {
            let argv: Vec<&str> = params
                .get("argv")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default();
            json!({ "text": run_command(&argv, out, pending, counter) })
        }
        "plugin/shutdown" => return (Some(json!({ "id": id, "result": {} })), true),
        _ => {
            let error = json!({ "code": -32601, "message": "method not found" });
            return (Some(json!({ "id": id, "error": error })), false);
        }
    };
    (Some(json!({ "id": id, "result": result })), false)
}

fn main() {
    if std::env::args().nth(1).as_deref() == Some("manifest") {
        println!("{}", manifest());
        return;
    }
    let stdout = Arc::new(Mutex::new(std::io::stdout()));
    let pending: Pending = Arc::new(Mutex::new(HashMap::new()));
    let counter = Arc::new(Mutex::new(0u64));

    // Reader thread: host→sidecar `host/*` replies arrive with a string id and
    // no method; route them to whoever is waiting. Numeric-id requests go to
    // the main loop.
    let (work_tx, work_rx) = mpsc::channel::<Value>();
    let reader_pending = pending.clone();
    let reader = std::thread::spawn(move || {
        let stdin = std::io::stdin();
        for line in stdin.lock().lines() {
            let Ok(line) = line else { break };
            let Ok(v) = serde_json::from_str::<Value>(&line) else { continue };
            if v.get("method").and_then(|m| m.as_str()) == Some("plugin/shutdown") {
                break;
            }
            if let Some(id) = v.get("id").and_then(|i| i.as_str())
                && v.get("method").is_none()
                && let Some(tx) = reader_pending.lock().expect("pending").remove(id)
            {
                let _ = tx.send(v.get("result").cloned().unwrap_or(Value::Null));
                continue;
            }
            if work_tx.send(v).is_err() {
                break;
            }
        }
    });

    for req in work_rx {
        let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");
        // `plugin/shutdown` as a notification already stopped the reader; a
        // queued request copy still gets a reply.
        let (reply, exit) = handle(&req, &stdout, &pending, &counter);
        if let Some(reply) = reply {
            let mut o = stdout.lock().expect("stdout");
            let _ = writeln!(o, "{reply}");
            let _ = o.flush();
        }
        if exit {
            break;
        }
        let _ = method;
    }
    let _ = reader.join();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sha256_hex(s: &str) -> String {
        sha256(s.as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn sha256_known_vector() {
        assert_eq!(
            sha256_hex("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn b64url_and_urlencode() {
        assert_eq!(b64_encode(b"foob", false), "Zm9vYg==");
        assert_eq!(b64_encode(&[0xfb, 0xff], true), "-_8=");
        assert_eq!(urlencode("a b&c=1"), "a%20b%26c%3D1");
    }

    #[test]
    fn extract_code_shapes() {
        assert_eq!(extract_code("abc123"), Some("abc123".into()));
        assert_eq!(
            extract_code("http://127.0.0.1:43827/spotify/callback?code=XYZ789&state=s"),
            Some("XYZ789".into())
        );
        assert_eq!(extract_code(""), None);
        assert_eq!(extract_code("not a code with spaces"), None);
    }

    #[test]
    fn manifest_shape() {
        let (reply, _) = handle(
            &json!({"id": 1, "method": "plugin/manifest"}),
            &Arc::new(Mutex::new(std::io::stdout())),
            &Arc::new(Mutex::new(HashMap::new())),
            &Arc::new(Mutex::new(0)),
        );
        let m = reply.unwrap()["result"].clone();
        assert_eq!(m["name"], "spotify");
        assert_eq!(m["tools"][0]["name"], "spotify");
        assert_eq!(m["commands"], json!(["/spotify"]));
    }

    #[test]
    fn tool_without_token_is_clear_error() {
        let dir = std::env::temp_dir().join(format!("gray-spotify-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        unsafe { std::env::set_var("GRAY_HOME", &dir) };
        let r = call_tool("spotify", &json!({"action": "now"}));
        let e = r.unwrap_err();
        assert!(e.contains("/spotify auth"), "{e}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn bad_actions_error() {
        assert!(call_tool("spotify", &json!({"action": "bogus"})).unwrap_err().contains("unknown action"));
        assert!(call_tool("spotify", &json!({"action": "search"})).unwrap_err().contains("query"));
        assert!(call_tool("nope", &json!({})).unwrap_err().contains("unknown tool"));
    }
}
