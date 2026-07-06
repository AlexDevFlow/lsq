//! Loopback integration tests for the Download API (spec §5): a real HTTP
//! share server driven by real clients, plus the pull module against it.

use lsq::discovery::SelfDevice;
use lsq::proto::*;
use lsq::share::{ShareState, SharedFile};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tempfile::TempDir;

struct ShareServer {
    addr: SocketAddr,
    #[allow(dead_code)]
    src: TempDir,
    handle: axum_server::Handle,
}

impl Drop for ShareServer {
    fn drop(&mut self) {
        self.handle.shutdown();
    }
}

/// Start a share server offering the given files (name, content).
async fn start_share(files: &[(&str, &[u8])], pin: Option<&str>) -> ShareServer {
    let src = TempDir::new().unwrap();
    let mut map = BTreeMap::new();
    for (i, (name, content)) in files.iter().enumerate() {
        let path = src.path().join(format!("src{i}.bin"));
        std::fs::write(&path, content).unwrap();
        let id = format!("f{i}");
        map.insert(
            id.clone(),
            SharedFile {
                dto: FileDto {
                    id,
                    file_name: name.to_string(),
                    size: content.len() as u64,
                    file_type: "application/octet-stream".into(),
                    sha256: None,
                    preview: None,
                    metadata: None,
                },
                path,
            },
        );
    }
    let me = SelfDevice {
        alias: "test-sharer".into(),
        fingerprint: "share-fp".into(),
        port: 0,
        protocol: Protocol::Http,
        download: true,
    };
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move { while rx.recv().await.is_some() {} });
    let state = Arc::new(ShareState {
        me,
        files: map,
        pin: pin.map(String::from),
        quiet: true,
        sessions: Default::default(),
        pin_guard: Default::default(),
        peers: Default::default(),
        events: tx,
    });
    let app = lsq::share::router(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let handle = axum_server::Handle::new();
    let h2 = handle.clone();
    tokio::spawn(async move {
        axum_server::bind("127.0.0.1:0".parse().unwrap())
            .handle(h2)
            .serve(app)
            .await
            .unwrap();
    });
    let addr = handle.listening().await.unwrap();
    ShareServer { addr, src, handle }
}

fn base(s: &ShareServer) -> String {
    format!("http://127.0.0.1:{}", s.addr.port())
}

fn client() -> reqwest::Client {
    reqwest::Client::new()
}

fn client_from(ip: &str) -> reqwest::Client {
    reqwest::Client::builder()
        .local_address(ip.parse::<std::net::IpAddr>().unwrap())
        .build()
        .unwrap()
}

async fn do_prepare(c: &reqwest::Client, s: &ShareServer) -> PrepareDownloadResponse {
    let resp = c
        .post(format!("{}{API_BASE}/prepare-download", base(s)))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    resp.json().await.unwrap()
}

// ------------------------------------------------------------ serve side

#[tokio::test]
async fn prepare_download_lists_files() {
    let s = start_share(&[("a.txt", b"hello"), ("b.bin", b"\x00\x01")], None).await;
    let prep = do_prepare(&client(), &s).await;
    assert!(!prep.session_id.is_empty());
    assert!(prep.info.download);
    assert_eq!(prep.info.alias, "test-sharer");
    assert_eq!(prep.files.len(), 2);
    assert_eq!(prep.files["f0"].file_name, "a.txt");
    assert_eq!(prep.files["f0"].size, 5);
}

#[tokio::test]
async fn download_delivers_exact_bytes() {
    let payload = vec![0xA7u8; 100_000];
    let s = start_share(&[("blob.bin", &payload)], None).await;
    let c = client();
    let prep = do_prepare(&c, &s).await;
    let resp = c
        .get(format!(
            "{}{API_BASE}/download?sessionId={}&fileId=f0",
            base(&s),
            prep.session_id
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()["content-length"],
        payload.len().to_string().as_str()
    );
    assert!(resp.headers()["content-disposition"]
        .to_str()
        .unwrap()
        .contains("blob.bin"));
    let body = resp.bytes().await.unwrap();
    assert_eq!(body.as_ref(), payload.as_slice());
}

#[tokio::test]
async fn download_can_run_in_parallel() {
    let payload = vec![0x55u8; 64 * 1024];
    let s = start_share(&[("x.bin", &payload), ("y.bin", &payload)], None).await;
    let c = client();
    let prep = do_prepare(&c, &s).await;
    let mut handles = Vec::new();
    for fid in ["f0", "f1", "f0"] {
        let c = c.clone();
        let url = format!(
            "{}{API_BASE}/download?sessionId={}&fileId={fid}",
            base(&s),
            prep.session_id
        );
        handles.push(tokio::spawn(async move {
            let r = c.get(url).send().await.unwrap();
            assert_eq!(r.status(), 200);
            r.bytes().await.unwrap().len()
        }));
    }
    for h in handles {
        assert_eq!(h.await.unwrap(), payload.len());
    }
}

#[tokio::test]
async fn download_auth_edges() {
    let s = start_share(&[("a.txt", b"x")], None).await;
    let c = client();
    let prep = do_prepare(&c, &s).await;

    // missing params
    let r = c
        .get(format!("{}{API_BASE}/download?fileId=f0", base(&s)))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400);

    // unknown session
    let r = c
        .get(format!(
            "{}{API_BASE}/download?sessionId=NOPE&fileId=f0",
            base(&s)
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);

    // unknown file id
    let r = c
        .get(format!(
            "{}{API_BASE}/download?sessionId={}&fileId=ghost",
            base(&s),
            prep.session_id
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
}

#[tokio::test]
async fn session_is_bound_to_ip() {
    let s = start_share(&[("a.txt", b"x")], None).await;
    let c1 = client_from("127.0.0.1");
    let resp = c1
        .post(format!("{}{API_BASE}/prepare-download", base(&s)))
        .send()
        .await
        .unwrap();
    let prep: PrepareDownloadResponse = resp.json().await.unwrap();

    // download from another loopback IP with a stolen session id
    let c2 = client_from("127.0.0.2");
    let r = c2
        .get(format!(
            "{}{API_BASE}/download?sessionId={}&fileId=f0",
            base(&s),
            prep.session_id
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
}

#[tokio::test]
async fn session_reuse_skips_pin() {
    let s = start_share(&[("a.txt", b"x")], Some("123456")).await;
    let c = client();
    let url = format!("{}{API_BASE}/prepare-download", base(&s));

    // no PIN → 401
    let r = c.post(&url).send().await.unwrap();
    assert_eq!(r.status(), 401);
    // correct PIN → session
    let r = c.post(format!("{url}?pin=123456")).send().await.unwrap();
    assert_eq!(r.status(), 200);
    let prep: PrepareDownloadResponse = r.json().await.unwrap();
    // refresh with sessionId, no PIN → accepted (spec §5.2)
    let r = c
        .post(format!("{url}?sessionId={}", prep.session_id))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let again: PrepareDownloadResponse = r.json().await.unwrap();
    assert_eq!(again.session_id, prep.session_id);
}

#[tokio::test]
async fn pin_rate_limit_applies_to_download_api() {
    let s = start_share(&[("a.txt", b"x")], Some("42")).await;
    let c = client();
    let url = format!("{}{API_BASE}/prepare-download", base(&s));
    let r = c.post(format!("{url}?pin=00")).send().await.unwrap();
    assert_eq!(r.status(), 401);
    let r = c.post(format!("{url}?pin=11")).send().await.unwrap();
    assert_eq!(r.status(), 401);
    let r = c.post(format!("{url}?pin=22")).send().await.unwrap();
    assert_eq!(r.status(), 429);
    // locked out even with the correct PIN
    let r = c.post(format!("{url}?pin=42")).send().await.unwrap();
    assert_eq!(r.status(), 429);
}

#[tokio::test]
async fn browser_page_lists_files_with_session_links() {
    let s = start_share(&[("report final.pdf", b"pdf")], None).await;
    let c = client();
    let r = c.get(base(&s)).send().await.unwrap();
    assert_eq!(r.status(), 200);
    let html = r.text().await.unwrap();
    assert!(html.contains("report final.pdf"));
    assert!(html.contains("/api/localsend/v2/download?sessionId="));
    // refreshing reuses the same session instead of growing the map
    let sid = html
        .split("sessionId=")
        .nth(1)
        .unwrap()
        .split('&')
        .next()
        .unwrap()
        .to_string();
    let html2 = c.get(base(&s)).send().await.unwrap().text().await.unwrap();
    assert!(html2.contains(&sid));
}

#[tokio::test]
async fn browser_page_escapes_html_in_names() {
    let s = start_share(&[("<img src=x>.txt", b"x")], None).await;
    let html = client().get(base(&s)).send().await.unwrap().text().await.unwrap();
    assert!(!html.contains("<img src=x>"));
    assert!(html.contains("&lt;img src=x&gt;"));
}

#[tokio::test]
async fn browser_page_shows_pin_form_until_correct() {
    let s = start_share(&[("a.txt", b"x")], Some("777")).await;
    let c = client();
    let html = c.get(base(&s)).send().await.unwrap();
    assert_eq!(html.status(), 401);
    assert!(html.text().await.unwrap().contains("<form"));
    let ok = c.get(format!("{}/?pin=777", base(&s))).send().await.unwrap();
    assert_eq!(ok.status(), 200);
    assert!(ok.text().await.unwrap().contains("a.txt"));
}

#[tokio::test]
async fn info_reports_download_active() {
    let s = start_share(&[("a.txt", b"x")], None).await;
    let r = client()
        .get(format!("{}{API_BASE}/info", base(&s)))
        .send()
        .await
        .unwrap();
    let body: InfoResponse = r.json().await.unwrap();
    assert!(body.download);
    assert_eq!(body.alias, "test-sharer");
}

// ------------------------------------------------------------ pull side

#[tokio::test]
async fn pull_module_end_to_end() {
    let a = vec![1u8; 10_000];
    let b = b"second file".to_vec();
    let s = start_share(&[("data.bin", &a), ("note.txt", &b)], None).await;
    let dest = TempDir::new().unwrap();
    let outcome = lsq::pull::pull_files(&base(&s), dest.path(), None, None, true)
        .await
        .unwrap();
    assert_eq!(outcome.fetched, 2);
    assert_eq!(std::fs::read(dest.path().join("data.bin")).unwrap(), a);
    assert_eq!(std::fs::read(dest.path().join("note.txt")).unwrap(), b);
    // no leftover temp files
    assert!(!std::fs::read_dir(dest.path()).unwrap().any(|e| {
        e.unwrap().file_name().to_string_lossy().ends_with(".part")
    }));
}

#[tokio::test]
async fn pull_uses_pin_and_reports_wrong_pin() {
    let s = start_share(&[("a.txt", b"x")], Some("9999")).await;
    let dest = TempDir::new().unwrap();
    let err = lsq::pull::pull_files(&base(&s), dest.path(), None, None, true)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("PIN"));
    assert!(!err.unreachable);
    let outcome = lsq::pull::pull_files(&base(&s), dest.path(), Some("9999"), None, true)
        .await
        .unwrap();
    assert_eq!(outcome.fetched, 1);
}

#[tokio::test]
async fn pull_never_overwrites_existing_files() {
    let s = start_share(&[("keep.txt", b"new")], None).await;
    let dest = TempDir::new().unwrap();
    std::fs::write(dest.path().join("keep.txt"), b"original").unwrap();
    lsq::pull::pull_files(&base(&s), dest.path(), None, None, true)
        .await
        .unwrap();
    assert_eq!(std::fs::read(dest.path().join("keep.txt")).unwrap(), b"original");
    assert_eq!(std::fs::read(dest.path().join("keep (2).txt")).unwrap(), b"new");
}

#[tokio::test]
async fn pull_sanitizes_hostile_names() {
    let s = start_share(&[("../../../tmp/lsq-pull-escape.txt", b"x")], None).await;
    let dest = TempDir::new().unwrap();
    lsq::pull::pull_files(&base(&s), dest.path(), None, None, true)
        .await
        .unwrap();
    assert!(!std::path::Path::new("/tmp/lsq-pull-escape.txt").exists());
    assert!(dest.path().join("lsq-pull-escape.txt").exists());
}

#[tokio::test]
async fn pull_respects_max_size() {
    let s = start_share(&[("big.bin", &vec![0u8; 5000])], None).await;
    let dest = TempDir::new().unwrap();
    let err = lsq::pull::pull_files(&base(&s), dest.path(), None, Some(1024), true)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("max-size"));
    assert_eq!(std::fs::read_dir(dest.path()).unwrap().count(), 0);
}

#[tokio::test]
async fn pull_marks_dead_peer_unreachable() {
    // unroutable TEST-NET address → connect timeout flagged as unreachable
    let dest = TempDir::new().unwrap();
    let start = std::time::Instant::now();
    let err = lsq::pull::pull_files("http://192.0.2.1:53317", dest.path(), None, None, true)
        .await
        .unwrap_err();
    assert!(err.unreachable);
    assert!(start.elapsed() < std::time::Duration::from_secs(30));
}

/// A server that declares one size but streams more must be cut off with no
/// partial file left behind (the peer controls both values; trust neither).
#[tokio::test]
async fn pull_rejects_oversized_body_from_lying_server() {
    use axum::{routing::get, routing::post, Json, Router};
    let declared = 4u64;
    let app = Router::new()
        .route(
            "/api/localsend/v2/prepare-download",
            post(move || async move {
                Json(serde_json::json!({
                    "info": { "alias": "liar", "version": "2.1", "fingerprint": "liar-fp", "download": true },
                    "sessionId": "sid",
                    "files": { "f": { "id": "f", "fileName": "small.txt",
                                       "size": declared, "fileType": "text/plain" } }
                }))
            }),
        )
        .route(
            "/api/localsend/v2/download",
            get(|| async { vec![b'x'; 4096] }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let dest = TempDir::new().unwrap();
    let err = lsq::pull::pull_files(&format!("http://{addr}"), dest.path(), None, None, true)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("exceeds declared size"));
    assert_eq!(std::fs::read_dir(dest.path()).unwrap().count(), 0);
}
