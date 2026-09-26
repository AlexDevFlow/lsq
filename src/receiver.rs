//! Receive mode: HTTPS/HTTP server implementing the Upload API (spec §4)
//! plus /register and /info.
//!
//! Session rules (mirroring the official app):
//! - one active session at a time → 409 for others
//! - session bound to the sender's IP; uploads from other IPs → 403
//! - per-file random tokens; wrong/missing token → 403
//! - declared size enforced during streaming; overrun kills the transfer
//! - writes go to a unique `.lsq-*.part`, fsync + atomic rename on success
//! - PIN failures are rate-limited
//! - abandoned/stalled sessions time out so one peer can't wedge the slot

use crate::proto::*;
use crate::sanitize::{dedup_path, sanitize_file_name};
use axum::{
    body::Body,
    extract::{ConnectInfo, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use futures_util::StreamExt;
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

// Official app (common.dart checkPin): per-IP counter, max 3 attempts,
// missing/empty PIN does not increment, no time-based reset.
const PIN_MAX_ATTEMPTS: u32 = 3;
// Bound the PIN attempt map so probing IPs can't grow memory forever.
const PIN_ATTEMPTS_MAX_IPS: usize = 4096;
// No data for this long on an in-flight upload → abort and free the slot.
const UPLOAD_READ_TIMEOUT: Duration = Duration::from_secs(30);
// A session with no upload progress for this long is reaped.
pub const SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
// How often the reaper checks for stale sessions.
pub const REAPER_INTERVAL: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AcceptMode {
    /// Accept every session (daemon mode / --yes).
    Yes,
    /// Decline every session (used by tests; a GUI-less "do not disturb").
    No,
    /// Ask on the terminal.
    Prompt,
}

#[derive(Clone)]
pub struct ReceiverConfig {
    pub dest: PathBuf,
    pub accept: AcceptMode,
    pub pin: Option<String>,
    pub quiet: bool,
    /// Reject a transfer whose declared total exceeds this many bytes.
    pub max_bytes: Option<u64>,
}

#[derive(Debug)]
pub struct FileSlot {
    pub dto: FileDto,
    pub token: String,
    pub done: bool,
}

pub struct Session {
    pub id: String,
    pub sender_ip: IpAddr,
    pub sender_alias: String,
    pub files: HashMap<String, FileSlot>, // fileId -> slot
    pub last_activity: Instant,
}

/// The single session slot. `Reserved` marks the brief window while an accept
/// decision is being made, so a concurrent sender gets an immediate 409
/// instead of blocking on the lock or racing the prompt.
#[derive(Default)]
pub enum Slot {
    #[default]
    Empty,
    Reserved,
    Active(Session),
}

#[derive(Default)]
pub struct PinGuard {
    attempts: HashMap<IpAddr, u32>,
}

/// Outcome of one PIN check against the guard.
pub enum PinCheck {
    Ok,
    Unauthorized,
    TooMany,
}

impl PinGuard {
    /// Official checkPin semantics (common.dart): per-IP counter, max 3
    /// attempts, missing/empty PIN does not increment, a correct PIN resets
    /// the counter for that IP. Shared by the upload and download APIs.
    pub fn check(&mut self, required: &str, provided: Option<&str>, ip: IpAddr) -> PinCheck {
        let prior = self.attempts.get(&ip).copied().unwrap_or(0);
        if prior >= PIN_MAX_ATTEMPTS {
            return PinCheck::TooMany;
        }
        match provided {
            Some(pin) if constant_time_eq(pin.as_bytes(), required.as_bytes()) => {
                self.attempts.remove(&ip);
                PinCheck::Ok
            }
            Some(pin) if !pin.is_empty() => {
                // Only now do we allocate a map entry, and only if there's
                // room. Missing/empty PIN never inserts, which caps growth.
                if prior > 0 || self.attempts.len() < PIN_ATTEMPTS_MAX_IPS {
                    let n = self.attempts.entry(ip).or_insert(0);
                    *n += 1;
                    if *n >= PIN_MAX_ATTEMPTS {
                        return PinCheck::TooMany;
                    }
                }
                PinCheck::Unauthorized
            }
            // Missing/empty PIN: unauthorized without incrementing.
            _ => PinCheck::Unauthorized,
        }
    }
}

pub struct AppState {
    pub me: crate::discovery::SelfDevice,
    pub cfg: ReceiverConfig,
    pub session: Mutex<Slot>,
    pub pin_guard: Mutex<PinGuard>,
    pub peers: crate::discovery::PeerMap,
    /// Notifies the CLI loop about accepted files (for logging).
    pub events: tokio::sync::mpsc::UnboundedSender<String>,
}

type Shared = Arc<AppState>;

pub fn router(state: Shared) -> Router {
    Router::new()
        .route(&format!("{API_BASE}/register"), post(register))
        .route(&format!("{API_BASE}/prepare-upload"), post(prepare_upload))
        .route(&format!("{API_BASE}/upload"), post(upload))
        .route(&format!("{API_BASE}/cancel"), post(cancel))
        .route(&format!("{API_BASE}/info"), get(info))
        // v1 path aliases: old clients hit /api/localsend/v1/info
        .route("/api/localsend/v1/info", get(info))
        .with_state(state)
}

pub(crate) fn err(code: StatusCode, msg: &str) -> Response {
    (code, Json(serde_json::json!({ "message": msg }))).into_response()
}

/// Background task: free the session slot if the active transfer stalls or is
/// abandoned, so a single peer cannot permanently block the receiver.
pub async fn reap_stale_sessions(state: Shared) {
    loop {
        tokio::time::sleep(REAPER_INTERVAL).await;
        let mut slot = state.session.lock().await;
        if let Slot::Active(s) = &*slot {
            if s.last_activity.elapsed() > SESSION_IDLE_TIMEOUT {
                let _ = state.events.send(format!(
                    "session from {} timed out after {}s idle; freeing slot",
                    s.sender_alias,
                    SESSION_IDLE_TIMEOUT.as_secs()
                ));
                *slot = Slot::Empty;
            }
        }
    }
}

/// Removes a temp file on drop unless disarmed, so an interrupted (dropped)
/// transfer future never leaves an orphan `.lsq-*.part` behind.
pub(crate) struct TempFileGuard {
    path: Option<PathBuf>,
}

impl TempFileGuard {
    fn new(path: PathBuf) -> Self {
        Self { path: Some(path) }
    }
    pub(crate) fn disarm(mut self) {
        self.path = None;
    }
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        if let Some(p) = self.path.take() {
            let _ = std::fs::remove_file(p);
        }
    }
}

/// Constant-time byte comparison for the PIN gate. Length is allowed to
/// leak (PIN length is not the secret); content comparison is time-invariant.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

// ---------------------------------------------------------------- handlers

async fn register(
    State(state): State<Shared>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    body: Option<Json<DeviceInfo>>,
) -> Response {
    if let Some(Json(peer)) = body {
        if peer.fingerprint_or_default() != state.me.fingerprint {
            // /register is the authenticated (TCP, cert-bearing) path, so its
            // address for a fingerprint is trusted over bare UDP announces.
            crate::discovery::record_peer_trusted(
                &state.peers,
                peer.to_announce(),
                addr.ip(),
            )
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

#[derive(Deserialize)]
struct PinQuery {
    pin: Option<String>,
}

/// Returns Some(error response) if the PIN gate fails.
async fn check_pin(state: &Shared, q: &PinQuery, ip: IpAddr) -> Option<Response> {
    let required = state.cfg.pin.as_deref()?;
    let mut guard = state.pin_guard.lock().await;
    match guard.check(required, q.pin.as_deref(), ip) {
        PinCheck::Ok => None,
        PinCheck::Unauthorized => Some(err(StatusCode::UNAUTHORIZED, "Invalid pin.")),
        PinCheck::TooMany => Some(err(StatusCode::TOO_MANY_REQUESTS, "Too many attempts.")),
    }
}

/// Owned summary handed to the (blocking) accept prompt so it needs no borrow.
struct AcceptRequest {
    alias: String,
    files: Vec<(String, u64)>,
    total: u64,
}

async fn prepare_upload(
    State(state): State<Shared>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Query(q): Query<PinQuery>,
    body: axum::body::Bytes,
) -> Response {
    if let Some(resp) = check_pin(&state, &q, addr.ip()).await {
        return resp;
    }
    let req: PrepareUploadRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            let _ = state.events.send(format!("prepare-upload rejected: {e}"));
            return err(StatusCode::BAD_REQUEST, "Request body malformed");
        }
    };
    if req.files.is_empty() {
        return err(
            StatusCode::BAD_REQUEST,
            "Request must contain at least one file",
        );
    }

    // Saturating sum: attacker-controlled sizes must not overflow.
    let total: u64 = req.files.values().fold(0u64, |a, f| a.saturating_add(f.size));
    if let Some(max) = state.cfg.max_bytes {
        if total > max {
            return err(StatusCode::FORBIDDEN, "Transfer exceeds size limit");
        }
    }

    // Reserve the slot without holding the lock across the accept decision.
    {
        let mut slot = state.session.lock().await;
        match &*slot {
            Slot::Empty => *slot = Slot::Reserved,
            _ => return err(StatusCode::CONFLICT, "Blocked by another session"),
        }
    }

    let accepted = match state.cfg.accept {
        AcceptMode::Yes => true,
        AcceptMode::No => false,
        AcceptMode::Prompt => {
            let ar = AcceptRequest {
                alias: req.info.alias.clone(),
                files: req
                    .files
                    .values()
                    .map(|f| (f.file_name.clone(), f.size))
                    .collect(),
                total,
            };
            // Run the blocking terminal prompt off the async runtime.
            tokio::task::spawn_blocking(move || prompt_accept(ar))
                .await
                .unwrap_or(false)
        }
    };

    if !accepted {
        let mut slot = state.session.lock().await;
        *slot = Slot::Empty; // release the reservation
        return err(StatusCode::FORBIDDEN, "File request declined by recipient");
    }

    // Official app: UUID v4 for both session id and file tokens.
    let session_id = uuid::Uuid::new_v4().to_string();
    let mut files = HashMap::new();
    let mut tokens = BTreeMap::new();
    for (id, dto) in &req.files {
        let token = uuid::Uuid::new_v4().to_string();
        tokens.insert(id.clone(), token.clone());
        files.insert(id.clone(), FileSlot { dto: dto.clone(), token, done: false });
    }
    let _ = state.events.send(format!(
        "session from {} ({}): {} file(s), {} bytes",
        req.info.alias,
        addr.ip(),
        files.len(),
        total
    ));
    {
        let mut slot = state.session.lock().await;
        *slot = Slot::Active(Session {
            id: session_id.clone(),
            sender_ip: addr.ip(),
            sender_alias: req.info.alias.clone(),
            files,
            last_activity: Instant::now(),
        });
    }

    Json(PrepareUploadResponse { session_id, files: tokens }).into_response()
}

fn prompt_accept(req: AcceptRequest) -> bool {
    use std::io::Write;
    eprintln!(
        "\nIncoming from \"{}\", {} file(s), {} bytes:",
        req.alias,
        req.files.len(),
        req.total
    );
    for (name, size) in &req.files {
        eprintln!("  - {name} ({size} bytes)");
    }
    eprint!("Accept? [y/N] ");
    std::io::stderr().flush().ok();
    let mut line = String::new();
    if std::io::stdin().read_line(&mut line).is_err() {
        return false;
    }
    matches!(line.trim(), "y" | "Y" | "yes")
}

#[derive(Deserialize)]
struct UploadQuery {
    #[serde(rename = "sessionId")]
    session_id: Option<String>,
    #[serde(rename = "fileId")]
    file_id: Option<String>,
    token: Option<String>,
}

async fn upload(
    State(state): State<Shared>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Query(q): Query<UploadQuery>,
    body: Body,
) -> Response {
    let (Some(session_id), Some(file_id), Some(token)) =
        (q.session_id, q.file_id, q.token)
    else {
        return err(StatusCode::BAD_REQUEST, "Missing parameters");
    };

    // Validate under lock, then stream without holding the lock.
    // Error responses mirror the official app.
    let (dto, dest_dir) = {
        let mut slot = state.session.lock().await;
        let Slot::Active(session) = &mut *slot else {
            return err(StatusCode::CONFLICT, "No session");
        };
        if session.sender_ip != addr.ip() {
            return err(
                StatusCode::FORBIDDEN,
                &format!("Invalid IP address: {}", addr.ip()),
            );
        }
        if session.id != session_id {
            return err(StatusCode::FORBIDDEN, "Invalid session id");
        }
        let Some(fslot) = session.files.get_mut(&file_id) else {
            return err(StatusCode::FORBIDDEN, "Invalid token");
        };
        if fslot.token != token || fslot.done {
            return err(StatusCode::FORBIDDEN, "Invalid token");
        }
        session.last_activity = Instant::now();
        (fslot.dto.clone(), state.cfg.dest.clone())
    };

    // Stream to a unique temp file first (unique names make parallel uploads
    // of same-named files safe). The guard removes the temp file if anything
    // below returns early or the future is dropped.
    let (part_path, part_guard) = match stream_to_part(&dto, &dest_dir, body.into_data_stream()).await {
        Ok(pair) => pair,
        Err(e) => {
            let _ = state.events.send(format!("upload failed: {e}"));
            // Protocol 2.2: a checksum mismatch is the sender's problem to
            // retry, not a receiver fault, and has its own status code.
            if e.downcast_ref::<ChecksumMismatch>().is_some() {
                return err(StatusCode::UNPROCESSABLE_ENTITY, "Checksum mismatch");
            }
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Could not save file. Check receiving device for more information.",
            );
        }
    };

    // Finalize atomically under the lock: re-validate, mark done BEFORE the
    // rename so a retry can never produce a duplicate delivery, rename,
    // and free the slot when the whole session is complete.
    let mut slot = state.session.lock().await;
    let Slot::Active(session) = &mut *slot else {
        return err(StatusCode::CONFLICT, "No session"); // guard cleans the temp file
    };
    let valid = session.id == session_id
        && session
            .files
            .get(&file_id)
            .is_some_and(|f| f.token == token && !f.done);
    if !valid {
        return err(StatusCode::CONFLICT, "No session");
    }
    let safe_name = sanitize_file_name(&dto.file_name);
    let final_path = dedup_path(&dest_dir, &safe_name);
    session.files.get_mut(&file_id).unwrap().done = true;
    if let Err(e) = tokio::fs::rename(&part_path, &final_path).await {
        session.files.get_mut(&file_id).unwrap().done = false;
        let _ = state.events.send(format!("rename failed: {e}"));
        return err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Could not save file. Check receiving device for more information.",
        );
    }
    part_guard.disarm(); // renamed into place, don't delete it
    session.last_activity = Instant::now();
    let all_done = session.files.values().all(|f| f.done);
    let _ = state.events.send(format!(
        "received {} from {}",
        final_path.display(),
        session.sender_alias
    ));
    if all_done {
        *slot = Slot::Empty; // session complete, free for the next sender
        let _ = state.events.send("session complete".into());
    }
    StatusCode::OK.into_response()
}

/// A received body did not match the `sha256` its sender declared.
/// Protocol 2.2 answers this with 422 so the sender can tell a corrupted
/// transfer apart from a fault on the receiving side.
#[derive(Debug, thiserror::Error)]
#[error("sha256 mismatch")]
pub(crate) struct ChecksumMismatch;

/// Stream a body to a unique `.lsq-*.part` temp file in the dest dir,
/// enforcing the declared size (and sha256 when provided) and an idle read
/// timeout. Returns the temp path plus an armed cleanup guard; on any error
/// the temp file is removed and the error returned. Also used by pull, which
/// feeds it an HTTP response body instead of a request body.
pub(crate) async fn stream_to_part<S, E>(
    dto: &FileDto,
    dest_dir: &Path,
    stream: S,
) -> anyhow::Result<(PathBuf, TempFileGuard)>
where
    S: futures_util::Stream<Item = Result<bytes::Bytes, E>>,
    E: std::fmt::Display,
{
    tokio::fs::create_dir_all(dest_dir).await?;
    let part_path = dest_dir.join(format!(".lsq-{}.part", uuid::Uuid::new_v4()));
    let guard = TempFileGuard::new(part_path.clone());

    let mut file = tokio::fs::File::create(&part_path).await?;
    let mut hasher = dto.sha256.as_ref().map(|_| sha2::Sha256::default());
    let mut written: u64 = 0;
    let mut stream = std::pin::pin!(stream);
    loop {
        // Idle timeout so a slow-loris / stalled peer can't wedge the slot.
        let next = tokio::time::timeout(UPLOAD_READ_TIMEOUT, stream.next()).await;
        let chunk = match next {
            Err(_) => anyhow::bail!("transfer stalled (no data for {}s)", UPLOAD_READ_TIMEOUT.as_secs()),
            Ok(None) => break,
            Ok(Some(c)) => c.map_err(|e| anyhow::anyhow!("body read: {e}"))?,
        };
        written += chunk.len() as u64;
        if written > dto.size {
            anyhow::bail!("body exceeds declared size ({written} > {})", dto.size);
        }
        if let Some(h) = hasher.as_mut() {
            use sha2::Digest;
            h.update(&chunk);
        }
        file.write_all(&chunk).await?;
    }
    if written != dto.size {
        anyhow::bail!("incomplete transfer ({written} of {} bytes)", dto.size);
    }
    if let (Some(h), Some(expected)) = (hasher, &dto.sha256) {
        use sha2::Digest;
        let actual: String = h.finalize().iter().map(|b| format!("{b:02x}")).collect();
        if !actual.eq_ignore_ascii_case(expected) {
            return Err(ChecksumMismatch.into());
        }
    }
    // fsync the data before the caller makes the final name visible, so a crash
    // can't leave a correctly-named but truncated file.
    file.sync_all().await?;
    Ok((part_path, guard))
}

#[derive(Deserialize)]
struct CancelQuery {
    #[serde(rename = "sessionId")]
    session_id: Option<String>,
}

async fn cancel(
    State(state): State<Shared>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Query(q): Query<CancelQuery>,
) -> Response {
    let mut slot = state.session.lock().await;
    if let Slot::Active(session) = &*slot {
        // Only the session's sender may cancel it.
        let matches_session = q.session_id.as_deref() == Some(session.id.as_str());
        if matches_session && session.sender_ip == addr.ip() {
            let _ = state
                .events
                .send(format!("session cancelled by {}", session.sender_alias));
            *slot = Slot::Empty;
        }
    }
    StatusCode::OK.into_response()
}
