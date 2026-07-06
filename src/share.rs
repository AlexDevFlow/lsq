//! Share mode: HTTP server implementing the Download API (spec §5), so
//! browsers and other LocalSend clients can pull files from this device.
//!
//! Plain HTTP by design: the spec uses unencrypted HTTP here because browsers
//! reject self-signed certificates. Sessions are cheap (id, IP, timestamp),
//! bounded, and each is pinned to the IP that opened it.

use crate::proto::*;
use crate::receiver::{err, PinCheck, PinGuard};
use axum::{
    body::Body,
    extract::{ConnectInfo, Query, State},
    http::{header, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;

// Bound the session map; a full map is purged of expired entries first.
const MAX_SESSIONS: usize = 4096;
const SESSION_TTL: std::time::Duration = std::time::Duration::from_secs(60 * 60);

/// One file offered for download.
pub struct SharedFile {
    pub dto: FileDto,
    pub path: PathBuf,
}

pub struct DownloadSession {
    pub ip: IpAddr,
    pub created: Instant,
}

pub struct ShareState {
    pub me: crate::discovery::SelfDevice,
    /// fileId -> file. BTreeMap keeps listing order stable.
    pub files: BTreeMap<String, SharedFile>,
    pub pin: Option<String>,
    pub quiet: bool,
    pub sessions: Mutex<HashMap<String, DownloadSession>>,
    pub pin_guard: Mutex<PinGuard>,
    pub peers: crate::discovery::PeerMap,
    /// Notifies the CLI loop about downloads (for logging).
    pub events: tokio::sync::mpsc::UnboundedSender<String>,
}

type Shared = Arc<ShareState>;

pub fn router(state: Shared) -> Router {
    Router::new()
        .route("/", get(index))
        .route(&format!("{API_BASE}/prepare-download"), post(prepare_download))
        .route(&format!("{API_BASE}/download"), get(download))
        .route(&format!("{API_BASE}/register"), post(register))
        .route(&format!("{API_BASE}/info"), get(info))
        .route("/api/localsend/v1/info", get(info))
        .with_state(state)
}

/// Look up a session; Some(ip-bound hit) only if the caller IP matches.
async fn session_valid(state: &Shared, id: &str, ip: IpAddr) -> bool {
    let sessions = state.sessions.lock().await;
    sessions.get(id).is_some_and(|s| s.ip == ip)
}

/// Create a session for `ip`, or None if the map stays full after purging
/// expired entries (the caller answers 429).
async fn create_session(state: &Shared, ip: IpAddr) -> Option<String> {
    let mut sessions = state.sessions.lock().await;
    if sessions.len() >= MAX_SESSIONS {
        sessions.retain(|_, s| s.created.elapsed() < SESSION_TTL);
        if sessions.len() >= MAX_SESSIONS {
            return None;
        }
    }
    let id = uuid::Uuid::new_v4().to_string();
    sessions.insert(id.clone(), DownloadSession { ip, created: Instant::now() });
    Some(id)
}

/// Reuse the caller's existing session if one exists (page refreshes should
/// not grow the map), otherwise create one.
async fn session_for(state: &Shared, ip: IpAddr) -> Option<String> {
    {
        let sessions = state.sessions.lock().await;
        if let Some((id, _)) = sessions.iter().find(|(_, s)| s.ip == ip) {
            return Some(id.clone());
        }
    }
    create_session(state, ip).await
}

fn prepare_response(state: &ShareState, session_id: &str) -> PrepareDownloadResponse {
    PrepareDownloadResponse {
        info: state.me.device_info(),
        session_id: session_id.to_string(),
        files: state
            .files
            .iter()
            .map(|(id, f)| (id.clone(), f.dto.clone()))
            .collect(),
    }
}

/// Returns Some(error response) if the PIN gate fails.
async fn check_pin(state: &Shared, pin: Option<&str>, ip: IpAddr) -> Option<Response> {
    let required = state.pin.as_deref()?;
    let mut guard = state.pin_guard.lock().await;
    match guard.check(required, pin, ip) {
        PinCheck::Ok => None,
        PinCheck::Unauthorized => Some(err(StatusCode::UNAUTHORIZED, "Invalid pin.")),
        PinCheck::TooMany => Some(err(StatusCode::TOO_MANY_REQUESTS, "Too many attempts.")),
    }
}

// ---------------------------------------------------------------- handlers

#[derive(Deserialize)]
struct PrepareDownloadQuery {
    pin: Option<String>,
    #[serde(rename = "sessionId")]
    session_id: Option<String>,
}

async fn prepare_download(
    State(state): State<Shared>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Query(q): Query<PrepareDownloadQuery>,
) -> Response {
    // A valid existing session (browser refresh, spec §5.2) skips the PIN gate.
    if let Some(sid) = &q.session_id {
        if session_valid(&state, sid, addr.ip()).await {
            return Json(prepare_response(&state, sid)).into_response();
        }
    }
    if let Some(resp) = check_pin(&state, q.pin.as_deref(), addr.ip()).await {
        return resp;
    }
    let Some(sid) = create_session(&state, addr.ip()).await else {
        return err(StatusCode::TOO_MANY_REQUESTS, "Too many requests");
    };
    let _ = state
        .events
        .send(format!("download session opened by {}", addr.ip()));
    Json(prepare_response(&state, &sid)).into_response()
}

#[derive(Deserialize)]
struct DownloadQuery {
    #[serde(rename = "sessionId")]
    session_id: Option<String>,
    #[serde(rename = "fileId")]
    file_id: Option<String>,
}

async fn download(
    State(state): State<Shared>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Query(q): Query<DownloadQuery>,
) -> Response {
    let (Some(session_id), Some(file_id)) = (q.session_id, q.file_id) else {
        return err(StatusCode::BAD_REQUEST, "Missing parameters");
    };
    if !session_valid(&state, &session_id, addr.ip()).await {
        return err(StatusCode::FORBIDDEN, "Invalid session id");
    }
    let Some(f) = state.files.get(&file_id) else {
        return err(StatusCode::FORBIDDEN, "Invalid file id");
    };
    let file = match tokio::fs::File::open(&f.path).await {
        Ok(file) => file,
        Err(e) => {
            let _ = state.events.send(format!("cannot open {}: {e}", f.path.display()));
            return err(StatusCode::INTERNAL_SERVER_ERROR, "Cannot read file");
        }
    };
    let _ = state
        .events
        .send(format!("{} downloading {}", addr.ip(), f.dto.file_name));
    let stream = tokio_util::io::ReaderStream::new(file);
    (
        [
            (header::CONTENT_LENGTH, f.dto.size.to_string()),
            (header::CONTENT_TYPE, f.dto.file_type.clone()),
            (header::CONTENT_DISPOSITION, content_disposition(&f.dto.file_name)),
        ],
        Body::from_stream(stream),
    )
        .into_response()
}

async fn register(
    State(state): State<Shared>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    body: Option<Json<DeviceInfo>>,
) -> Response {
    if let Some(Json(peer)) = body {
        if peer.fingerprint_or_default() != state.me.fingerprint {
            crate::discovery::record_peer_trusted(&state.peers, peer.to_announce(), addr.ip())
                .await;
        }
    }
    let me = state.me.device_info();
    Json(RegisterResponse {
        alias: me.alias,
        version: me.version.unwrap_or_else(|| PROTOCOL_VERSION.into()),
        device_model: me.device_model,
        device_type: me.device_type,
        fingerprint: me.fingerprint.unwrap_or_default(),
        download: me.download,
    })
    .into_response()
}

async fn info(State(state): State<Shared>) -> Json<InfoResponse> {
    let me = state.me.device_info();
    Json(InfoResponse {
        alias: me.alias,
        version: me.version.unwrap_or_else(|| PROTOCOL_VERSION.into()),
        device_model: me.device_model,
        device_type: me.device_type,
        fingerprint: me.fingerprint.unwrap_or_default(),
        download: me.download,
    })
}

// ---------------------------------------------------------------- browser page

#[derive(Deserialize)]
struct IndexQuery {
    pin: Option<String>,
}

/// Minimal file listing for browsers (spec §5.1). With a PIN set, the page
/// shows a form until the correct PIN arrives; attempts share the same
/// rate-limited guard as the API.
async fn index(
    State(state): State<Shared>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Query(q): Query<IndexQuery>,
) -> Response {
    if let Some(resp) = check_pin(&state, q.pin.as_deref(), addr.ip()).await {
        let status = resp.status();
        let body = if status == StatusCode::TOO_MANY_REQUESTS {
            page("Too many attempts", "<p>Too many wrong PINs. Ask the sender to restart the share.</p>".into())
        } else {
            let note = if q.pin.is_some() { "<p>Wrong PIN, try again.</p>" } else { "" };
            page(
                "PIN required",
                format!(
                    "{note}<form method=\"get\" action=\"/\">\
                     <label>PIN <input name=\"pin\" autofocus></label> \
                     <button>Open</button></form>"
                ),
            )
        };
        return (status, Html(body)).into_response();
    }
    let Some(sid) = session_for(&state, addr.ip()).await else {
        return err(StatusCode::TOO_MANY_REQUESTS, "Too many requests");
    };
    let mut items = String::new();
    for (id, f) in &state.files {
        items.push_str(&format!(
            "<li><a href=\"{API_BASE}/download?sessionId={}&fileId={}\" download>{}</a> \
             <small>({})</small></li>\n",
            html_escape(&sid),
            html_escape(&percent_encode(id)),
            html_escape(&f.dto.file_name),
            human_size(f.dto.size),
        ));
    }
    let body = page(
        &format!("Files from {}", html_escape(&state.me.alias)),
        format!("<ul>\n{items}</ul>"),
    );
    Html(body).into_response()
}

fn page(title: &str, body: String) -> String {
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <title>{title}</title>\
         <style>body{{font-family:sans-serif;max-width:40em;margin:2em auto;padding:0 1em}}\
         li{{margin:.4em 0}}</style></head>\
         <body><h1>{title}</h1>{body}</body></html>"
    )
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// RFC 3986 percent-encoding of everything outside the unreserved set.
pub fn percent_encode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// Content-Disposition with an ASCII fallback name plus the RFC 5987 form,
/// so non-ASCII names survive without producing an invalid header value.
fn content_disposition(name: &str) -> String {
    let ascii: String = name
        .chars()
        .map(|c| if c.is_ascii_graphic() || c == ' ' { c } else { '_' })
        .collect::<String>()
        .replace(['"', '\\'], "_");
    format!(
        "attachment; filename=\"{ascii}\"; filename*=UTF-8''{}",
        percent_encode(name)
    )
}

pub fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = bytes as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{bytes} B")
    } else {
        format!("{v:.1} {}", UNITS[i])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_encode_covers_reserved_and_utf8() {
        assert_eq!(percent_encode("abc-123._~"), "abc-123._~");
        assert_eq!(percent_encode("a b&c"), "a%20b%26c");
        assert_eq!(percent_encode("é"), "%C3%A9");
    }

    #[test]
    fn content_disposition_is_ascii_only() {
        let h = content_disposition("写真 🎉.png");
        assert!(h.is_ascii(), "header value must be ASCII: {h}");
        assert!(h.contains("filename*=UTF-8''%E5%86%99"));
        let h = content_disposition("evil\".txt");
        assert!(!h.contains("\"evil\""));
    }

    #[test]
    fn html_escape_neutralizes_markup() {
        assert_eq!(html_escape("<b>&\"x\""), "&lt;b&gt;&amp;&quot;x&quot;");
    }

    #[test]
    fn human_size_rounds_sensibly() {
        assert_eq!(human_size(0), "0 B");
        assert_eq!(human_size(999), "999 B");
        assert_eq!(human_size(4096), "4.0 KB");
        assert_eq!(human_size(4_155_972), "4.0 MB");
    }
}
