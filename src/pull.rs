//! Pull mode: client side of the Download API (spec §5). Fetches the file
//! list with prepare-download, then streams each file to disk with the same
//! protections as receive (declared-size enforcement, name sanitization,
//! collision rename, atomic rename from a temp file).

use crate::proto::*;
use crate::receiver::stream_to_part;
use crate::sanitize::{dedup_path, sanitize_file_name};
use crate::share::percent_encode;
use anyhow::{bail, Context, Result};
use futures_util::StreamExt;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use std::path::Path;
use std::time::Duration;

#[derive(Debug)]
pub struct PullOutcome {
    pub fetched: usize,
    pub total_bytes: u64,
}

/// Error from a pull attempt. `unreachable` is true only when prepare-download
/// never got a response, the one case where an HTTPS to HTTP retry makes
/// sense for a bare IP target.
#[derive(Debug)]
pub struct PullError {
    pub unreachable: bool,
    source: anyhow::Error,
}

impl PullError {
    fn unreachable(e: anyhow::Error) -> Self {
        Self { unreachable: true, source: e }
    }
    fn rejected(e: anyhow::Error) -> Self {
        Self { unreachable: false, source: e }
    }
}

impl std::fmt::Display for PullError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#}", self.source)
    }
}

impl std::error::Error for PullError {}

/// Same slow-transfer floor as send: scale the per-file timeout to its size.
fn download_timeout(size: u64) -> Duration {
    let secs = 30 + size / (128 * 1024);
    Duration::from_secs(secs.min(6 * 3600))
}

/// Download everything a peer offers. `base` is e.g. "http://192.168.1.5:53317".
pub async fn pull_files(
    base: &str,
    dest: &Path,
    pin: Option<&str>,
    max_bytes: Option<u64>,
    quiet: bool,
) -> std::result::Result<PullOutcome, PullError> {
    let client = crate::sender::insecure_client().map_err(PullError::rejected)?;
    let base = base.trim_end_matches('/');

    // 1. prepare-download
    let mut url = format!("{base}{API_BASE}/prepare-download");
    if let Some(pin) = pin {
        url = format!("{url}?pin={}", percent_encode(pin));
    }
    let resp = client
        .post(&url)
        .timeout(Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| {
            PullError::unreachable(
                anyhow::Error::new(e).context(format!("cannot reach {base}")),
            )
        })?;

    let prep: PrepareDownloadResponse = match resp.status().as_u16() {
        200 => resp.json().await.map_err(|e| {
            PullError::rejected(anyhow::Error::new(e).context("invalid prepare-download response"))
        })?,
        401 => return Err(PullError::rejected(anyhow::anyhow!("PIN required or invalid PIN (use --pin)"))),
        403 => return Err(PullError::rejected(anyhow::anyhow!("download rejected by the peer"))),
        404 => return Err(PullError::rejected(anyhow::anyhow!("peer does not offer downloads (no Download API)"))),
        429 => return Err(PullError::rejected(anyhow::anyhow!("too many requests, wait a moment and retry"))),
        code => return Err(PullError::rejected(anyhow::anyhow!("prepare-download failed: HTTP {code}"))),
    };
    if prep.files.is_empty() {
        return Err(PullError::rejected(anyhow::anyhow!("peer is not sharing any files")));
    }

    // Saturating sum: peer-controlled sizes must not overflow.
    let total: u64 = prep.files.values().fold(0u64, |a, f| a.saturating_add(f.size));
    if let Some(max) = max_bytes {
        if total > max {
            return Err(PullError::rejected(anyhow::anyhow!(
                "declared total ({total} bytes) exceeds --max-size ({max})"
            )));
        }
    }
    if !quiet {
        eprintln!(
            "pulling {} file(s), {} bytes from {}",
            prep.files.len(),
            total,
            prep.info.alias
        );
    }

    // 2. download each file
    let progress = MultiProgress::new();
    if quiet {
        progress.set_draw_target(indicatif::ProgressDrawTarget::hidden());
    }
    let mut fetched = 0usize;
    let mut fetched_bytes = 0u64;
    for (id, dto) in &prep.files {
        let bar = progress.add(ProgressBar::new(dto.size));
        if let Ok(style) = ProgressStyle::with_template(
            "{msg:20!} [{bar:30}] {bytes}/{total_bytes} {bytes_per_sec}",
        ) {
            bar.set_style(style.progress_chars("=> "));
        }
        bar.set_message(dto.file_name.clone());
        match download_one(&client, base, &prep.session_id, id, dto, dest, &bar).await {
            Ok(()) => {
                bar.finish();
                fetched += 1;
                fetched_bytes = fetched_bytes.saturating_add(dto.size);
            }
            Err(e) => {
                bar.abandon_with_message(format!("FAILED: {}", dto.file_name));
                return Err(PullError::rejected(e.context("pull aborted")));
            }
        }
    }
    Ok(PullOutcome { fetched, total_bytes: fetched_bytes })
}

async fn download_one(
    client: &reqwest::Client,
    base: &str,
    session_id: &str,
    file_id: &str,
    dto: &FileDto,
    dest: &Path,
    bar: &ProgressBar,
) -> Result<()> {
    let url = format!(
        "{base}{API_BASE}/download?sessionId={}&fileId={}",
        percent_encode(session_id),
        percent_encode(file_id),
    );
    let resp = client
        .get(&url)
        .timeout(download_timeout(dto.size))
        .send()
        .await
        .with_context(|| format!("download {}", dto.file_name))?;
    match resp.status().as_u16() {
        200 => {}
        403 => bail!("peer rejected the download session (403)"),
        code => bail!("download {} failed: HTTP {code}", dto.file_name),
    }

    let bar2 = bar.clone();
    let stream = resp.bytes_stream().inspect(move |chunk| {
        if let Ok(c) = chunk {
            bar2.inc(c.len() as u64);
        }
    });
    // Same path as receive: temp file, size/sha enforcement, atomic rename.
    let (part_path, guard) = stream_to_part(dto, dest, stream).await?;
    let safe_name = sanitize_file_name(&dto.file_name);
    let final_path = dedup_path(dest, &safe_name);
    tokio::fs::rename(&part_path, &final_path)
        .await
        .with_context(|| format!("rename to {}", final_path.display()))?;
    guard.disarm();
    Ok(())
}
