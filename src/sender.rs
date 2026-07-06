//! Send mode: prepare-upload → parallel uploads → cancel on failure (spec §4).

use crate::discovery::{Peer, SelfDevice};
use crate::proto::*;
use anyhow::{bail, Context, Result};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use rand::distributions::{Alphanumeric, DistString};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// HTTP client that accepts self-signed certificates. LocalSend peers use
/// self-signed certs by design (spec §2); trust is anchored on fingerprints,
/// not on CAs. LAN-local threat model, same as the official app.
pub fn insecure_client() -> Result<reqwest::Client> {
    client_with_identity(None)
}

/// Like the app, the client presents its own certificate. Newer LocalSend
/// builds require a client cert, so send it even though v2.1 doesn't check it.
pub fn client_with_identity(id: Option<&crate::certs::Identity>) -> Result<reqwest::Client> {
    let mut b = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .connect_timeout(Duration::from_secs(5))
        .user_agent(concat!("lsq/", env!("CARGO_PKG_VERSION")));
    if let Some(id) = id {
        let pem = format!("{}{}", id.cert_pem, id.key_pem);
        b = b.identity(reqwest::Identity::from_pem(pem.as_bytes())?);
    }
    Ok(b.build()?)
}

#[derive(Debug)]
pub struct OutFile {
    pub id: String,
    pub path: PathBuf,
    pub dto: FileDto,
}

/// Expand CLI path arguments into a flat file list. Directories recurse;
/// file ids are random (official app also uses opaque ids).
pub fn collect_files(paths: &[PathBuf]) -> Result<Vec<OutFile>> {
    let mut out = Vec::new();
    for p in paths {
        if !p.exists() {
            bail!("no such file or directory: {}", p.display());
        }
        if p.is_dir() {
            collect_dir(p, &mut out)?;
        } else {
            push_file(p.clone(), file_name_of(p)?, &mut out)?;
        }
    }
    if out.is_empty() {
        bail!("nothing to send (empty directory?)");
    }
    Ok(out)
}

fn collect_dir(dir: &Path, out: &mut Vec<OutFile>) -> Result<()> {
    for entry in std::fs::read_dir(dir).with_context(|| format!("read {}", dir.display()))? {
        let path = entry?.path();
        if path.is_dir() {
            collect_dir(&path, out)?;
        } else if path.is_file() {
            push_file(path.clone(), file_name_of(&path)?, out)?;
        }
    }
    Ok(())
}

fn file_name_of(p: &Path) -> Result<String> {
    Ok(p.file_name()
        .context("path has no file name")?
        .to_string_lossy()
        .into_owned())
}

fn push_file(path: PathBuf, name: String, out: &mut Vec<OutFile>) -> Result<()> {
    let meta = std::fs::metadata(&path)?;
    let id = Alphanumeric.sample_string(&mut rand::thread_rng(), 16);
    let mime = mime_guess::from_path(&path).first_or_octet_stream();
    out.push(OutFile {
        dto: FileDto {
            id: id.clone(),
            file_name: name,
            size: meta.len(),
            file_type: mime.essence_str().to_string(),
            sha256: None, // official app skips hashing for speed; same here
            preview: None,
            metadata: None,
        },
        id,
        path,
    });
    Ok(())
}

pub fn base_url(peer: &Peer) -> String {
    let scheme = match peer.info.protocol_or_default() {
        Protocol::Https => "https",
        Protocol::Http => "http",
    };
    format!("{scheme}://{}:{}", peer.addr, peer.info.port_or(DEFAULT_PORT))
}

#[derive(Debug)]
pub struct SendOutcome {
    pub accepted: usize,
    pub sent: usize,
    pub skipped: usize,
}

/// Error from a send attempt. `unreachable` is true only when we never got a
/// prepare-upload response (connection-level failure), the one case where an
/// HTTPS→HTTP fallback is meaningful. Protocol rejections and mid-transfer
/// failures are NOT unreachable and must not trigger a blind re-send.
#[derive(Debug)]
pub struct SendError {
    pub unreachable: bool,
    source: anyhow::Error,
}

impl SendError {
    fn unreachable(e: anyhow::Error) -> Self {
        Self { unreachable: true, source: e }
    }
    fn rejected(e: anyhow::Error) -> Self {
        Self { unreachable: false, source: e }
    }
}

impl std::fmt::Display for SendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#}", self.source)
    }
}

impl std::error::Error for SendError {}

/// Upper bound on one file's upload, scaled to size assuming a slow ~128 KiB/s
/// floor, so a receiver that stops reading fails instead of hanging.
fn upload_timeout(size: u64) -> Duration {
    let secs = 30 + size / (128 * 1024);
    Duration::from_secs(secs.min(6 * 3600))
}

pub async fn send_files(
    me: &SelfDevice,
    peer: &Peer,
    files: Vec<OutFile>,
    pin: Option<&str>,
    quiet: bool,
    identity: Option<&crate::certs::Identity>,
) -> std::result::Result<SendOutcome, SendError> {
    let client = client_with_identity(identity).map_err(SendError::rejected)?;
    let base = base_url(peer);

    // 1. prepare-upload
    let mut dtos = BTreeMap::new();
    for f in &files {
        dtos.insert(f.id.clone(), f.dto.clone());
    }
    let req = PrepareUploadRequest { info: me.device_info(), files: dtos };
    let mut url = format!("{base}{API_BASE}/prepare-upload");
    if let Some(pin) = pin {
        url = format!("{url}?pin={pin}");
    }
    // A failure here means we never reached a responding server → unreachable.
    let resp = client
        .post(&url)
        .json(&req)
        .timeout(Duration::from_secs(300)) // receiver may wait on a human
        .send()
        .await
        .map_err(|e| {
            SendError::unreachable(
                anyhow::Error::new(e)
                    .context(format!("cannot reach {} at {base}", peer.info.alias)),
            )
        })?;

    let status = resp.status();
    let tokens: PrepareUploadResponse = match status.as_u16() {
        200 => resp
            .json()
            .await
            .map_err(|e| SendError::rejected(anyhow::Error::new(e).context("invalid prepare-upload response")))?,
        204 => return Ok(SendOutcome { accepted: 0, sent: 0, skipped: files.len() }),
        401 => return Err(SendError::rejected(anyhow::anyhow!("PIN required or invalid PIN (use --pin)"))),
        403 => return Err(SendError::rejected(anyhow::anyhow!("{} declined the transfer", peer.info.alias))),
        409 => return Err(SendError::rejected(anyhow::anyhow!("{} is busy with another session", peer.info.alias))),
        429 => return Err(SendError::rejected(anyhow::anyhow!("too many requests, wait a moment and retry"))),
        code => return Err(SendError::rejected(anyhow::anyhow!("prepare-upload failed: HTTP {code}"))),
    };

    // 2. upload accepted files (receiver may accept a subset)
    let accepted: Vec<&OutFile> = files
        .iter()
        .filter(|f| tokens.files.contains_key(&f.id))
        .collect();
    let skipped = files.len() - accepted.len();

    let progress = MultiProgress::new();
    if quiet {
        progress.set_draw_target(indicatif::ProgressDrawTarget::hidden());
    }
    let mut sent = 0usize;
    let mut failure: Option<anyhow::Error> = None;

    for f in &accepted {
        let token = &tokens.files[&f.id];
        let bar = progress.add(ProgressBar::new(f.dto.size));
        if let Ok(style) = ProgressStyle::with_template(
            "{msg:20!} [{bar:30}] {bytes}/{total_bytes} {bytes_per_sec}",
        ) {
            bar.set_style(style.progress_chars("=> "));
        }
        bar.set_message(f.dto.file_name.clone());

        match upload_one(&client, &base, &tokens.session_id, f, token, &bar).await {
            Ok(()) => {
                bar.finish();
                sent += 1;
            }
            Err(e) => {
                bar.abandon_with_message(format!("FAILED: {}", f.dto.file_name));
                failure = Some(e);
                break;
            }
        }
    }

    if let Some(e) = failure {
        // Best-effort cancel so the receiver frees the session.
        let _ = client
            .post(format!(
                "{base}{API_BASE}/cancel?sessionId={}",
                tokens.session_id
            ))
            .timeout(Duration::from_secs(5))
            .send()
            .await;
        // We had a session, so this is not "unreachable", no HTTP fallback.
        return Err(SendError::rejected(e.context("transfer aborted")));
    }

    Ok(SendOutcome { accepted: accepted.len(), sent, skipped })
}

async fn upload_one(
    client: &reqwest::Client,
    base: &str,
    session_id: &str,
    f: &OutFile,
    token: &str,
    bar: &ProgressBar,
) -> Result<()> {
    let file = tokio::fs::File::open(&f.path)
        .await
        .with_context(|| format!("open {}", f.path.display()))?;
    // Stream from disk with progress; never buffer the file in memory.
    let bar2 = bar.clone();
    let stream = tokio_util::io::ReaderStream::new(file).inspect(move |chunk| {
        if let Ok(c) = chunk {
            bar2.inc(c.len() as u64);
        }
    });
    let body = reqwest::Body::wrap_stream(stream);

    let url = format!(
        "{base}{API_BASE}/upload?sessionId={session_id}&fileId={}&token={token}",
        f.id
    );
    let resp = client
        .post(&url)
        .header(reqwest::header::CONTENT_LENGTH, f.dto.size)
        .timeout(upload_timeout(f.dto.size))
        .body(body)
        .send()
        .await
        .with_context(|| format!("upload {}", f.dto.file_name))?;

    match resp.status().as_u16() {
        200 => Ok(()),
        403 => bail!("receiver rejected the file token (403)"),
        409 => bail!("blocked by another session (409)"),
        code => bail!("upload failed: HTTP {code}"),
    }
}

use futures_util::StreamExt;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collect_files_rejects_missing_path() {
        let err = collect_files(&[PathBuf::from("/definitely/not/here")])
            .unwrap_err()
            .to_string();
        assert!(err.contains("no such file"));
    }

    #[test]
    fn collect_files_recurses_directories() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("sub")).unwrap();
        std::fs::write(dir.path().join("a.txt"), b"aaa").unwrap();
        std::fs::write(dir.path().join("sub/b.png"), b"bbbb").unwrap();
        let files = collect_files(&[dir.path().to_path_buf()]).unwrap();
        assert_eq!(files.len(), 2);
        let names: Vec<_> = files.iter().map(|f| f.dto.file_name.as_str()).collect();
        assert!(names.contains(&"a.txt"));
        assert!(names.contains(&"b.png"));
        let png = files.iter().find(|f| f.dto.file_name == "b.png").unwrap();
        assert_eq!(png.dto.file_type, "image/png");
        assert_eq!(png.dto.size, 4);
    }

    #[test]
    fn collect_files_rejects_empty_dir() {
        let dir = tempfile::tempdir().unwrap();
        assert!(collect_files(&[dir.path().to_path_buf()]).is_err());
    }
}
