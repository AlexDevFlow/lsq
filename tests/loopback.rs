//! Loopback integration tests: a real HTTPS receiver driven by real clients.

use lsq::certs;
use lsq::discovery::SelfDevice;
use lsq::proto::*;
use lsq::receiver::{AcceptMode, AppState, ReceiverConfig};
use lsq::sanitize::sanitize_file_name;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tempfile::TempDir;

struct TestServer {
    addr: SocketAddr,
    dest: TempDir,
    #[allow(dead_code)]
    state: Arc<AppState>,
    handle: axum_server::Handle,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.handle.shutdown();
    }
}

async fn start_server(accept: AcceptMode, pin: Option<&str>) -> TestServer {
    start_server_cfg(accept, pin, None).await
}

async fn start_server_cfg(
    accept: AcceptMode,
    pin: Option<&str>,
    max_bytes: Option<u64>,
) -> TestServer {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dest = TempDir::new().unwrap();
    let identity = certs::generate_identity("test").unwrap();
    let me = SelfDevice {
        alias: "test-receiver".into(),
        fingerprint: identity.fingerprint.clone(),
        port: 0,
        protocol: Protocol::Https,
        download: false,
    };
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move { while rx.recv().await.is_some() {} });
    let state = Arc::new(AppState {
        me,
        cfg: ReceiverConfig {
            dest: dest.path().to_path_buf(),
            accept,
            pin: pin.map(String::from),
            quiet: true,
            max_bytes,
        },
        session: Default::default(),
        pin_guard: Default::default(),
        peers: Default::default(),
        events: tx,
    });
    let app = lsq::receiver::router(state.clone())
        .into_make_service_with_connect_info::<SocketAddr>();
    let tls = axum_server::tls_rustls::RustlsConfig::from_pem(
        identity.cert_pem.clone().into_bytes(),
        identity.key_pem.clone().into_bytes(),
    )
    .await
    .unwrap();
    let handle = axum_server::Handle::new();
    let h2 = handle.clone();
    tokio::spawn(async move {
        axum_server::bind_rustls("127.0.0.1:0".parse().unwrap(), tls)
            .handle(h2)
            .serve(app)
            .await
            .unwrap();
    });
    let addr = handle.listening().await.unwrap();
    TestServer { addr, dest, state, handle }
}

fn client() -> reqwest::Client {
    lsq::sender::insecure_client().unwrap()
}

fn client_from(ip: &str) -> reqwest::Client {
    reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .local_address(ip.parse::<std::net::IpAddr>().unwrap())
        .build()
        .unwrap()
}

fn base(s: &TestServer) -> String {
    format!("https://127.0.0.1:{}", s.addr.port())
}

fn device_info() -> DeviceInfo {
    DeviceInfo {
        alias: "test-sender".into(),
        version: Some("2.1".into()),
        device_model: Some("test".into()),
        device_type: Some(DeviceType::Headless),
        fingerprint: Some("sender-fp".into()),
        port: Some(53317),
        protocol: Some(Protocol::Https),
        download: false,
    }
}

fn file_dto(id: &str, name: &str, content: &[u8]) -> FileDto {
    FileDto {
        id: id.into(),
        file_name: name.into(),
        size: content.len() as u64,
        file_type: "application/octet-stream".into(),
        sha256: None,
        preview: None,
        metadata: None,
    }
}

fn prepare_req(files: &[(&str, &str, &[u8])]) -> PrepareUploadRequest {
    let mut map = BTreeMap::new();
    for (id, name, content) in files {
        map.insert(id.to_string(), file_dto(id, name, content));
    }
    PrepareUploadRequest { info: device_info(), files: map }
}

async fn do_prepare(
    c: &reqwest::Client,
    s: &TestServer,
    files: &[(&str, &str, &[u8])],
) -> PrepareUploadResponse {
    let resp = c
        .post(format!("{}{API_BASE}/prepare-upload", base(s)))
        .json(&prepare_req(files))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    resp.json().await.unwrap()
}

async fn do_upload(
    c: &reqwest::Client,
    s: &TestServer,
    session: &PrepareUploadResponse,
    file_id: &str,
    body: &[u8],
) -> u16 {
    c.post(format!(
        "{}{API_BASE}/upload?sessionId={}&fileId={file_id}&token={}",
        base(s),
        session.session_id,
        session.files.get(file_id).map(String::as_str).unwrap_or("MISSING")
    ))
    .body(body.to_vec())
    .send()
    .await
    .unwrap()
    .status()
    .as_u16()
}

fn dest_file(s: &TestServer, name: &str) -> PathBuf {
    s.dest.path().join(name)
}

fn no_part_files(dir: &Path) -> bool {
    !std::fs::read_dir(dir).unwrap().any(|e| {
        e.unwrap().file_name().to_string_lossy().ends_with(".part")
    })
}

// ------------------------------------------------------------ happy paths

#[tokio::test]
async fn happy_path_two_files() {
    let s = start_server(AcceptMode::Yes, None).await;
    let c = client();
    let sess = do_prepare(&c, &s, &[("f1", "hello.txt", b"hello"), ("f2", "data.bin", b"\x00\x01\x02")]).await;
    assert_eq!(sess.files.len(), 2);
    assert_eq!(do_upload(&c, &s, &sess, "f1", b"hello").await, 200);
    assert_eq!(do_upload(&c, &s, &sess, "f2", b"\x00\x01\x02").await, 200);
    assert_eq!(std::fs::read(dest_file(&s, "hello.txt")).unwrap(), b"hello");
    assert_eq!(std::fs::read(dest_file(&s, "data.bin")).unwrap(), b"\x00\x01\x02");
    assert!(no_part_files(s.dest.path()));
    // session freed → a new prepare succeeds
    let _ = do_prepare(&c, &s, &[("g", "next.txt", b"x")]).await;
}

#[tokio::test]
async fn zero_byte_file() {
    let s = start_server(AcceptMode::Yes, None).await;
    let c = client();
    let sess = do_prepare(&c, &s, &[("f", "empty.txt", b"")]).await;
    assert_eq!(do_upload(&c, &s, &sess, "f", b"").await, 200);
    assert_eq!(std::fs::read(dest_file(&s, "empty.txt")).unwrap().len(), 0);
}

#[tokio::test]
async fn unicode_filename_preserved() {
    let s = start_server(AcceptMode::Yes, None).await;
    let c = client();
    let sess = do_prepare(&c, &s, &[("f", "写真 🎉.png", b"img")]).await;
    assert_eq!(do_upload(&c, &s, &sess, "f", b"img").await, 200);
    assert!(dest_file(&s, "写真 🎉.png").exists());
}

#[tokio::test]
async fn parallel_uploads_same_session() {
    let s = start_server(AcceptMode::Yes, None).await;
    let c = client();
    let specs: Vec<(String, String, Vec<u8>)> = (0..8)
        .map(|i| (format!("f{i}"), format!("file{i}.dat"), vec![i as u8; 4096]))
        .collect();
    let refs: Vec<(&str, &str, &[u8])> = specs
        .iter()
        .map(|(a, b, c)| (a.as_str(), b.as_str(), c.as_slice()))
        .collect();
    let sess = do_prepare(&c, &s, &refs).await;
    let mut handles = Vec::new();
    for (id, _, content) in &specs {
        let c = c.clone();
        let url = format!(
            "{}{API_BASE}/upload?sessionId={}&fileId={id}&token={}",
            base(&s), sess.session_id, sess.files[id]
        );
        let body = content.clone();
        handles.push(tokio::spawn(async move {
            c.post(url).body(body).send().await.unwrap().status().as_u16()
        }));
    }
    for h in handles {
        assert_eq!(h.await.unwrap(), 200);
    }
    for (_, name, content) in &specs {
        assert_eq!(&std::fs::read(dest_file(&s, name)).unwrap(), content);
    }
}

#[tokio::test]
async fn same_filename_twice_in_one_session() {
    let s = start_server(AcceptMode::Yes, None).await;
    let c = client();
    let sess = do_prepare(&c, &s, &[("a", "x.txt", b"first"), ("b", "x.txt", b"second")]).await;
    assert_eq!(do_upload(&c, &s, &sess, "a", b"first").await, 200);
    assert_eq!(do_upload(&c, &s, &sess, "b", b"second").await, 200);
    // official collision pattern: second file becomes "x (2).txt"
    let one = std::fs::read(dest_file(&s, "x.txt")).unwrap();
    let two = std::fs::read(dest_file(&s, "x (2).txt")).unwrap();
    assert_ne!(one, two);
}

#[tokio::test]
async fn existing_file_never_overwritten() {
    let s = start_server(AcceptMode::Yes, None).await;
    std::fs::write(dest_file(&s, "keep.txt"), b"original").unwrap();
    let c = client();
    let sess = do_prepare(&c, &s, &[("f", "keep.txt", b"new")]).await;
    assert_eq!(do_upload(&c, &s, &sess, "f", b"new").await, 200);
    assert_eq!(std::fs::read(dest_file(&s, "keep.txt")).unwrap(), b"original");
    assert_eq!(std::fs::read(dest_file(&s, "keep (2).txt")).unwrap(), b"new");
}

#[tokio::test]
async fn sha256_verified_when_provided() {
    let s = start_server(AcceptMode::Yes, None).await;
    let c = client();
    // correct hash accepted
    let mut req = prepare_req(&[("f", "ok.txt", b"payload")]);
    req.files.get_mut("f").unwrap().sha256 =
        Some(certs::sha256_hex(b"payload"));
    let resp = c.post(format!("{}{API_BASE}/prepare-upload", base(&s)))
        .json(&req).send().await.unwrap();
    let sess: PrepareUploadResponse = resp.json().await.unwrap();
    assert_eq!(do_upload(&c, &s, &sess, "f", b"payload").await, 200);
    // Wrong hash rejected with 422 (protocol 2.2), file absent, no partials.
    // 422 and not 500: the transfer is the sender's to retry, and the
    // official server answers a checksum mismatch the same way.
    let mut req = prepare_req(&[("g", "bad.txt", b"payload")]);
    req.files.get_mut("g").unwrap().sha256 = Some("00".repeat(32));
    let resp = c.post(format!("{}{API_BASE}/prepare-upload", base(&s)))
        .json(&req).send().await.unwrap();
    let sess: PrepareUploadResponse = resp.json().await.unwrap();
    assert_eq!(do_upload(&c, &s, &sess, "g", b"payload").await, 422);
    assert!(!dest_file(&s, "bad.txt").exists());
    assert!(no_part_files(s.dest.path()));
}

// ------------------------------------------------------------ prepare-upload edges

#[tokio::test]
async fn malformed_json_is_400() {
    let s = start_server(AcceptMode::Yes, None).await;
    let resp = client()
        .post(format!("{}{API_BASE}/prepare-upload", base(&s)))
        .header("content-type", "application/json")
        .body("{not json")
        .send().await.unwrap();
    assert_eq!(resp.status(), 400);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["message"], "Request body malformed");
}

#[tokio::test]
async fn empty_file_map_is_400() {
    let s = start_server(AcceptMode::Yes, None).await;
    let req = PrepareUploadRequest { info: device_info(), files: BTreeMap::new() };
    let resp = client()
        .post(format!("{}{API_BASE}/prepare-upload", base(&s)))
        .json(&req).send().await.unwrap();
    assert_eq!(resp.status(), 400);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["message"], "Request must contain at least one file");
}

#[tokio::test]
async fn decline_is_403_with_official_message() {
    let s = start_server(AcceptMode::No, None).await;
    let resp = client()
        .post(format!("{}{API_BASE}/prepare-upload", base(&s)))
        .json(&prepare_req(&[("f", "x.txt", b"x")]))
        .send().await.unwrap();
    assert_eq!(resp.status(), 403);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["message"], "File request declined by recipient");
}

#[tokio::test]
async fn concurrent_session_is_409() {
    let s = start_server(AcceptMode::Yes, None).await;
    let c = client();
    let _sess = do_prepare(&c, &s, &[("f", "x.txt", b"x")]).await;
    let resp = c
        .post(format!("{}{API_BASE}/prepare-upload", base(&s)))
        .json(&prepare_req(&[("g", "y.txt", b"y")]))
        .send().await.unwrap();
    assert_eq!(resp.status(), 409);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["message"], "Blocked by another session");
}

// ------------------------------------------------------------ PIN

#[tokio::test]
async fn pin_flow_matches_official_semantics() {
    let s = start_server(AcceptMode::Yes, Some("123456")).await;
    let c = client();
    let url = format!("{}{API_BASE}/prepare-upload", base(&s));
    let req = prepare_req(&[("f", "x.txt", b"x")]);

    // missing PIN → 401 "Invalid pin." (does not count as attempt)
    for _ in 0..5 {
        let r = c.post(&url).json(&req).send().await.unwrap();
        assert_eq!(r.status(), 401);
        let b: serde_json::Value = r.json().await.unwrap();
        assert_eq!(b["message"], "Invalid pin.");
    }
    // wrong PINs increment; 3rd wrong → 429 "Too many attempts."
    let r = c.post(format!("{url}?pin=000000")).json(&req).send().await.unwrap();
    assert_eq!(r.status(), 401);
    let r = c.post(format!("{url}?pin=111111")).json(&req).send().await.unwrap();
    assert_eq!(r.status(), 401);
    let r = c.post(format!("{url}?pin=222222")).json(&req).send().await.unwrap();
    assert_eq!(r.status(), 429);
    let b: serde_json::Value = r.json().await.unwrap();
    assert_eq!(b["message"], "Too many attempts.");
    // even the correct PIN is now locked out for this IP
    let r = c.post(format!("{url}?pin=123456")).json(&req).send().await.unwrap();
    assert_eq!(r.status(), 429);
}

#[tokio::test]
async fn correct_pin_accepted_and_resets() {
    let s = start_server(AcceptMode::Yes, Some("42")).await;
    let c = client();
    let url = format!("{}{API_BASE}/prepare-upload", base(&s));
    let req = prepare_req(&[("f", "x.txt", b"x")]);
    let r = c.post(format!("{url}?pin=99")).json(&req).send().await.unwrap();
    assert_eq!(r.status(), 401);
    let r = c.post(format!("{url}?pin=42")).json(&req).send().await.unwrap();
    assert_eq!(r.status(), 200);
}

// ------------------------------------------------------------ upload auth edges

#[tokio::test]
async fn upload_without_session_is_409_no_session() {
    let s = start_server(AcceptMode::Yes, None).await;
    let resp = client()
        .post(format!(
            "{}{API_BASE}/upload?sessionId=zzz&fileId=f&token=t",
            base(&s)
        ))
        .body("data")
        .send().await.unwrap();
    assert_eq!(resp.status(), 409);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["message"], "No session");
}

#[tokio::test]
async fn upload_missing_params_is_400() {
    let s = start_server(AcceptMode::Yes, None).await;
    let c = client();
    let _sess = do_prepare(&c, &s, &[("f", "x.txt", b"x")]).await;
    let resp = c
        .post(format!("{}{API_BASE}/upload?sessionId=only", base(&s)))
        .body("data")
        .send().await.unwrap();
    assert_eq!(resp.status(), 400);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["message"], "Missing parameters");
}

#[tokio::test]
async fn wrong_token_wrong_session_wrong_file() {
    let s = start_server(AcceptMode::Yes, None).await;
    let c = client();
    let sess = do_prepare(&c, &s, &[("f1", "x.txt", b"x"), ("f2", "y.txt", b"y")]).await;

    // wrong token
    let r = c.post(format!(
        "{}{API_BASE}/upload?sessionId={}&fileId=f1&token=WRONG",
        base(&s), sess.session_id
    )).body("x").send().await.unwrap();
    assert_eq!(r.status(), 403);
    let b: serde_json::Value = r.json().await.unwrap();
    assert_eq!(b["message"], "Invalid token");

    // token of the other file
    let r = c.post(format!(
        "{}{API_BASE}/upload?sessionId={}&fileId=f1&token={}",
        base(&s), sess.session_id, sess.files["f2"]
    )).body("x").send().await.unwrap();
    assert_eq!(r.status(), 403);

    // wrong session id
    let r = c.post(format!(
        "{}{API_BASE}/upload?sessionId=NOPE&fileId=f1&token={}",
        base(&s), sess.files["f1"]
    )).body("x").send().await.unwrap();
    assert_eq!(r.status(), 403);
    let b: serde_json::Value = r.json().await.unwrap();
    assert_eq!(b["message"], "Invalid session id");

    // unknown file id
    let r = c.post(format!(
        "{}{API_BASE}/upload?sessionId={}&fileId=ghost&token={}",
        base(&s), sess.session_id, sess.files["f1"]
    )).body("x").send().await.unwrap();
    assert_eq!(r.status(), 403);
    // nothing was written
    assert!(!dest_file(&s, "x.txt").exists());
}

#[tokio::test]
async fn upload_from_different_ip_is_403() {
    let s = start_server(AcceptMode::Yes, None).await;
    let c1 = client_from("127.0.0.1");
    let resp = c1
        .post(format!("{}{API_BASE}/prepare-upload", base(&s)))
        .json(&prepare_req(&[("f", "x.txt", b"x")]))
        .send().await.unwrap();
    let sess: PrepareUploadResponse = resp.json().await.unwrap();

    // same session, different source IP (127.0.0.2 is loopback on Linux)
    let c2 = client_from("127.0.0.2");
    let r = c2.post(format!(
        "{}{API_BASE}/upload?sessionId={}&fileId=f&token={}",
        base(&s), sess.session_id, sess.files["f"]
    )).body("x").send().await.unwrap();
    assert_eq!(r.status(), 403);
    let b: serde_json::Value = r.json().await.unwrap();
    assert!(b["message"].as_str().unwrap().starts_with("Invalid IP address"));
}

#[tokio::test]
async fn duplicate_upload_after_success_is_403() {
    let s = start_server(AcceptMode::Yes, None).await;
    let c = client();
    let sess = do_prepare(&c, &s, &[("f", "x.txt", b"x"), ("g", "y.txt", b"y")]).await;
    assert_eq!(do_upload(&c, &s, &sess, "f", b"x").await, 200);
    // retry after success: token consumed
    assert_eq!(do_upload(&c, &s, &sess, "f", b"x").await, 403);
    // only one copy on disk
    assert!(dest_file(&s, "x.txt").exists());
    assert!(!dest_file(&s, "x (2).txt").exists());
}

// ------------------------------------------------------------ size enforcement

#[tokio::test]
async fn oversized_body_rejected_and_cleaned() {
    let s = start_server(AcceptMode::Yes, None).await;
    let c = client();
    let sess = do_prepare(&c, &s, &[("f", "small.txt", b"1234")]).await; // declared 4
    let status = do_upload(&c, &s, &sess, "f", &vec![b'x'; 4096]).await;
    assert_eq!(status, 500);
    assert!(!dest_file(&s, "small.txt").exists());
    assert!(no_part_files(s.dest.path()));
}

#[tokio::test]
async fn undersized_body_rejected_and_cleaned() {
    let s = start_server(AcceptMode::Yes, None).await;
    let c = client();
    let sess = do_prepare(&c, &s, &[("f", "big.txt", &vec![b'x'; 1000])]).await; // declared 1000
    // chunked stream that ends after 10 bytes
    let stream = futures_util::stream::iter(vec![Ok::<_, std::io::Error>(
        bytes::Bytes::from_static(b"0123456789"),
    )]);
    let r = c.post(format!(
        "{}{API_BASE}/upload?sessionId={}&fileId=f&token={}",
        base(&s), sess.session_id, sess.files["f"]
    ))
    .body(reqwest::Body::wrap_stream(stream))
    .send().await.unwrap();
    assert_eq!(r.status(), 500);
    assert!(!dest_file(&s, "big.txt").exists());
    assert!(no_part_files(s.dest.path()));
}

#[tokio::test]
async fn moderately_large_file_streams_fine() {
    let s = start_server(AcceptMode::Yes, None).await;
    let c = client();
    let payload = vec![0xABu8; 32 * 1024 * 1024]; // 32 MiB
    let sess = do_prepare(&c, &s, &[("f", "big.bin", &payload)]).await;
    assert_eq!(do_upload(&c, &s, &sess, "f", &payload).await, 200);
    let meta = std::fs::metadata(dest_file(&s, "big.bin")).unwrap();
    assert_eq!(meta.len(), payload.len() as u64);
}

// ------------------------------------------------------------ traversal / hostile names

#[tokio::test]
async fn traversal_names_stay_in_dest() {
    let s = start_server(AcceptMode::Yes, None).await;
    let c = client();
    let hostile = [
        ("t1", "../../../tmp/lsq-escape.txt"),
        ("t2", "/tmp/lsq-abs.txt"),
        ("t3", "..\\..\\lsq-win.txt"),
        ("t4", "CON"),
        ("t5", "evil\u{202E}txt.exe"),
    ];
    let specs: Vec<(&str, &str, &[u8])> =
        hostile.iter().map(|(id, n)| (*id, *n, b"x" as &[u8])).collect();
    let sess = do_prepare(&c, &s, &specs).await;
    for (id, _) in &hostile {
        assert_eq!(do_upload(&c, &s, &sess, id, b"x").await, 200);
    }
    // Nothing escaped the dest dir
    assert!(!Path::new("/tmp/lsq-escape.txt").exists());
    assert!(!Path::new("/tmp/lsq-abs.txt").exists());
    // Everything landed inside dest with sanitized names
    let entries: Vec<String> = std::fs::read_dir(s.dest.path()).unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(entries.len(), hostile.len());
    for (_, name) in &hostile {
        let expected = sanitize_file_name(name);
        assert!(
            entries.contains(&expected),
            "expected {expected:?} in {entries:?}"
        );
    }
}

// ------------------------------------------------------------ cancel

#[tokio::test]
async fn cancel_frees_session() {
    let s = start_server(AcceptMode::Yes, None).await;
    let c = client();
    let sess = do_prepare(&c, &s, &[("f", "x.txt", b"x")]).await;
    let r = c.post(format!(
        "{}{API_BASE}/cancel?sessionId={}", base(&s), sess.session_id
    )).send().await.unwrap();
    assert_eq!(r.status(), 200);
    // session gone: upload rejected, new prepare accepted
    assert_eq!(do_upload(&c, &s, &sess, "f", b"x").await, 409);
    let _ = do_prepare(&c, &s, &[("g", "y.txt", b"y")]).await;
}

#[tokio::test]
async fn cancel_from_other_ip_is_ignored() {
    let s = start_server(AcceptMode::Yes, None).await;
    let c1 = client_from("127.0.0.1");
    let resp = c1
        .post(format!("{}{API_BASE}/prepare-upload", base(&s)))
        .json(&prepare_req(&[("f", "x.txt", b"x")]))
        .send().await.unwrap();
    let sess: PrepareUploadResponse = resp.json().await.unwrap();

    let c2 = client_from("127.0.0.2");
    let _ = c2.post(format!(
        "{}{API_BASE}/cancel?sessionId={}", base(&s), sess.session_id
    )).send().await.unwrap();
    // session still alive for the legitimate sender
    let r = c1.post(format!(
        "{}{API_BASE}/upload?sessionId={}&fileId=f&token={}",
        base(&s), sess.session_id, sess.files["f"]
    )).body("x").send().await.unwrap();
    assert_eq!(r.status(), 200);
}

#[tokio::test]
async fn cancel_mid_stream_discards_partial() {
    let s = start_server(AcceptMode::Yes, None).await;
    let c = client();
    let sess = do_prepare(&c, &s, &[("f", "victim.txt", &[b'x'; 20])]).await;

    // Body: first chunk immediately, then wait so cancel lands mid-stream,
    // then the rest. Total equals declared size, so streaming succeeds and
    // the post-stream session check must catch the cancellation.
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<Result<bytes::Bytes, std::io::Error>>();
    tx.send(Ok(bytes::Bytes::from_static(&[b'x'; 10]))).unwrap();
    let upload = tokio::spawn({
        let c = c.clone();
        let url = format!(
            "{}{API_BASE}/upload?sessionId={}&fileId=f&token={}",
            base(&s), sess.session_id, sess.files["f"]
        );
        async move {
            c.post(url)
                .body(reqwest::Body::wrap_stream(
                    tokio_stream_compat(rx),
                ))
                .send().await.unwrap().status().as_u16()
        }
    });
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    let r = c.post(format!(
        "{}{API_BASE}/cancel?sessionId={}", base(&s), sess.session_id
    )).send().await.unwrap();
    assert_eq!(r.status(), 200);
    tx.send(Ok(bytes::Bytes::from_static(&[b'x'; 10]))).unwrap();
    drop(tx);

    assert_eq!(upload.await.unwrap(), 409);
    assert!(!dest_file(&s, "victim.txt").exists());
    assert!(no_part_files(s.dest.path()));
}

fn tokio_stream_compat(
    mut rx: tokio::sync::mpsc::UnboundedReceiver<Result<bytes::Bytes, std::io::Error>>,
) -> impl futures_util::Stream<Item = Result<bytes::Bytes, std::io::Error>> {
    async_stream_poll(move |cx| rx.poll_recv(cx))
}

fn async_stream_poll<T, F>(f: F) -> impl futures_util::Stream<Item = T>
where
    F: FnMut(&mut std::task::Context<'_>) -> std::task::Poll<Option<T>>,
{
    futures_util::stream::poll_fn(f)
}

// ------------------------------------------------------------ register / info

#[tokio::test]
async fn register_returns_own_info_and_records_peer() {
    let s = start_server(AcceptMode::Yes, None).await;
    let c = client();
    let r = c.post(format!("{}{API_BASE}/register", base(&s)))
        .json(&device_info())
        .send().await.unwrap();
    assert_eq!(r.status(), 200);
    let body: RegisterResponse = r.json().await.unwrap();
    assert_eq!(body.alias, "test-receiver");
    assert_eq!(body.version, PROTOCOL_VERSION);
    assert!(!body.fingerprint.is_empty());
}

#[tokio::test]
async fn info_route_v2_and_v1() {
    let s = start_server(AcceptMode::Yes, None).await;
    let c = client();
    for path in [format!("{API_BASE}/info"), "/api/localsend/v1/info".into()] {
        let r = c.get(format!("{}{path}", base(&s))).send().await.unwrap();
        assert_eq!(r.status(), 200);
        let body: InfoResponse = r.json().await.unwrap();
        assert_eq!(body.alias, "test-receiver");
    }
}

// ------------------------------------------------------------ full sender path

#[tokio::test]
async fn sender_module_end_to_end() {
    let s = start_server(AcceptMode::Yes, None).await;
    let src = TempDir::new().unwrap();
    std::fs::write(src.path().join("doc.pdf"), vec![7u8; 10_000]).unwrap();
    std::fs::create_dir(src.path().join("sub")).unwrap();
    std::fs::write(src.path().join("sub/nested.txt"), b"nested").unwrap();

    let identity = certs::generate_identity("sender").unwrap();
    let me = SelfDevice {
        alias: "e2e-sender".into(),
        fingerprint: identity.fingerprint.clone(),
        port: 53399,
        protocol: Protocol::Https,
        download: false,
    };
    let peer = lsq::discovery::Peer {
        info: Announce {
            alias: "test-receiver".into(),
            version: Some("2.1".into()),
            device_model: None,
            device_type: Some(DeviceType::Headless),
            fingerprint: "srv".into(),
            port: Some(s.addr.port()),
            protocol: Some(Protocol::Https),
            download: false,
            announce: false,
            announcement: None,
        },
        addr: "127.0.0.1".parse().unwrap(),
        last_seen: std::time::Instant::now(),
    };
    let files = lsq::sender::collect_files(&[src.path().to_path_buf()]).unwrap();
    assert_eq!(files.len(), 2);
    let outcome = lsq::sender::send_files(&me, &peer, files, None, true, Some(&identity))
        .await
        .unwrap();
    assert_eq!(outcome.sent, 2);
    assert_eq!(outcome.skipped, 0);
    assert_eq!(std::fs::read(dest_file(&s, "nested.txt")).unwrap(), b"nested");
    assert_eq!(std::fs::metadata(dest_file(&s, "doc.pdf")).unwrap().len(), 10_000);
}

#[tokio::test]
async fn sender_reports_decline_cleanly() {
    let s = start_server(AcceptMode::No, None).await;
    let src = TempDir::new().unwrap();
    std::fs::write(src.path().join("f.txt"), b"x").unwrap();
    let identity = certs::generate_identity("sender").unwrap();
    let me = SelfDevice {
        alias: "e2e-sender".into(),
        fingerprint: identity.fingerprint.clone(),
        port: 53399,
        protocol: Protocol::Https,
        download: false,
    };
    let peer = lsq::discovery::Peer {
        info: Announce {
            alias: "grumpy".into(),
            version: Some("2.1".into()),
            device_model: None,
            device_type: None,
            fingerprint: "srv".into(),
            port: Some(s.addr.port()),
            protocol: Some(Protocol::Https),
            download: false,
            announce: false,
            announcement: None,
        },
        addr: "127.0.0.1".parse().unwrap(),
        last_seen: std::time::Instant::now(),
    };
    let files = lsq::sender::collect_files(&[src.path().join("f.txt")]).unwrap();
    let err = lsq::sender::send_files(&me, &peer, files, None, true, Some(&identity))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("declined"));
}

#[tokio::test]
async fn sender_times_out_on_dead_receiver() {
    // unroutable TEST-NET address → connect timeout, not a hang
    let identity = certs::generate_identity("sender").unwrap();
    let me = SelfDevice {
        alias: "e2e-sender".into(),
        fingerprint: identity.fingerprint.clone(),
        port: 53399,
        protocol: Protocol::Https,
        download: false,
    };
    let peer = lsq::discovery::Peer {
        info: Announce {
            alias: "ghost".into(),
            version: Some("2.1".into()),
            device_model: None,
            device_type: None,
            fingerprint: "x".into(),
            port: Some(53317),
            protocol: Some(Protocol::Https),
            download: false,
            announce: false,
            announcement: None,
        },
        addr: "192.0.2.1".parse().unwrap(),
        last_seen: std::time::Instant::now(),
    };
    let src = TempDir::new().unwrap();
    std::fs::write(src.path().join("f.txt"), b"x").unwrap();
    let files = lsq::sender::collect_files(&[src.path().join("f.txt")]).unwrap();
    let start = std::time::Instant::now();
    let res = lsq::sender::send_files(&me, &peer, files, None, true, Some(&identity)).await;
    assert!(res.is_err());
    assert!(start.elapsed() < std::time::Duration::from_secs(30));
}

// ------------------------------------------------------------ limits & compat

/// A transfer whose declared total exceeds the configured cap is refused at
/// prepare-upload, before any bytes are streamed.
#[tokio::test]
async fn size_cap_rejects_oversized_declared_transfer() {
    let s = start_server_cfg(AcceptMode::Yes, None, Some(1024)).await;
    let c = client();
    // Declared 2000 bytes > 1024 cap.
    let resp = c
        .post(format!("{}{API_BASE}/prepare-upload", base(&s)))
        .json(&prepare_req(&[("f", "big.bin", &[0u8; 2000])]))
        .send().await.unwrap();
    assert_eq!(resp.status(), 403);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["message"], "Transfer exceeds size limit");
    // Under the cap still works.
    let sess = do_prepare(&c, &s, &[("g", "ok.bin", &[0u8; 500])]).await;
    assert_eq!(do_upload(&c, &s, &sess, "g", &[0u8; 500]).await, 200);
}

/// Sizes summing past u64::MAX must not panic or wrap to a small total. The
/// sum saturates, so with a cap set the transfer is refused, not mishandled.
#[tokio::test]
async fn declared_size_overflow_is_saturating() {
    let s = start_server_cfg(AcceptMode::Yes, None, Some(1_000_000)).await;
    let c = client();
    let mut req = prepare_req(&[("a", "a.bin", b""), ("b", "b.bin", b"")]);
    req.files.get_mut("a").unwrap().size = u64::MAX;
    req.files.get_mut("b").unwrap().size = 10;
    let resp = c
        .post(format!("{}{API_BASE}/prepare-upload", base(&s)))
        .json(&req).send().await.unwrap();
    // Saturated total (u64::MAX) exceeds the cap → clean 403, no panic/wrap.
    assert_eq!(resp.status(), 403);
}

/// A finished transfer frees the session slot for the next sender.
#[tokio::test]
async fn completed_transfer_frees_the_slot() {
    let s = start_server(AcceptMode::Yes, None).await;
    let c = client();
    let sess = do_prepare(&c, &s, &[("f", "slow.bin", &[0u8; 100])]).await;
    assert_eq!(do_upload(&c, &s, &sess, "f", &[0u8; 100]).await, 200);
    let _ = do_prepare(&c, &s, &[("g", "next.bin", b"x")]).await;
}

/// The reaper frees a session that was opened and then abandoned, so a later
/// sender isn't blocked.
#[tokio::test]
async fn reaper_frees_abandoned_session() {
    use lsq::receiver::{reap_stale_sessions, Slot};
    let s = start_server(AcceptMode::Yes, None).await;
    let c = client();
    // Open a session and never upload.
    let _sess = do_prepare(&c, &s, &[("f", "x.bin", b"x")]).await;
    // Backdate its activity so it is already stale.
    {
        let mut slot = s.state.session.lock().await;
        if let Slot::Active(session) = &mut *slot {
            session.last_activity = std::time::Instant::now()
                - lsq::receiver::SESSION_IDLE_TIMEOUT
                - std::time::Duration::from_secs(1);
        } else {
            panic!("expected an active session");
        }
    }
    // Run the reaper long enough for one tick.
    let st = s.state.clone();
    let reaper = tokio::spawn(async move { reap_stale_sessions(st).await });
    tokio::time::sleep(lsq::receiver::REAPER_INTERVAL + std::time::Duration::from_millis(500)).await;
    reaper.abort();
    // Slot must now be free; a new prepare succeeds.
    let _ = do_prepare(&c, &s, &[("g", "y.bin", b"y")]).await;
}

/// An announcement missing version/port/protocol and using only the legacy v1
/// `announcement` flag still parses and counts as a reply-worthy peer.
#[tokio::test]
async fn legacy_nullable_announce_is_accepted() {
    // Pure protocol-model check (no server needed): the receiver's discovery
    // parser must accept this shape.
    let json = r#"{"alias":"Legacy","fingerprint":"legacy-fp","announcement":true}"#;
    let ann: Announce = serde_json::from_str(json).unwrap();
    assert!(ann.should_reply());
    assert_eq!(ann.port_or(53317), 53317);
    assert_eq!(ann.protocol_or_default(), Protocol::Https);
}

/// A prepare-upload whose `info` omits fingerprint/version is accepted for v1
/// compatibility rather than rejected with a 400.
#[tokio::test]
async fn prepare_upload_accepts_minimal_info() {
    let s = start_server(AcceptMode::Yes, None).await;
    let body = serde_json::json!({
        "info": { "alias": "Old Peer" },
        "files": { "f": { "id": "f", "fileName": "x.txt", "size": 1, "fileType": "text/plain" } }
    });
    let resp = client()
        .post(format!("{}{API_BASE}/prepare-upload", base(&s)))
        .json(&body).send().await.unwrap();
    assert_eq!(resp.status(), 200, "minimal v1-style info must be accepted");
}
