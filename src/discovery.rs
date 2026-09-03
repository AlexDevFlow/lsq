//! Peer discovery: UDP multicast announce/listen (spec §3.1) with TCP
//! /register replies, plus an HTTP legacy fallback scan (spec §3.2).

use crate::proto::*;
use anyhow::{Context, Result};
use socket2::{Domain, Protocol as SockProtocol, Socket, Type};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

#[derive(Debug, Clone)]
pub struct Peer {
    pub info: Announce,
    pub addr: IpAddr,
    pub last_seen: Instant,
}

pub type PeerMap = Arc<Mutex<HashMap<String, Peer>>>; // key: fingerprint

const MAX_PEERS: usize = 1024; // bound the registry against announce storms

/// Everything needed to describe ourselves on the network.
#[derive(Clone)]
pub struct SelfDevice {
    pub alias: String,
    pub fingerprint: String,
    pub port: u16,
    pub protocol: Protocol,
    pub download: bool,
}

impl SelfDevice {
    pub fn announce(&self, announce: bool) -> Announce {
        Announce {
            alias: self.alias.clone(),
            version: Some(PROTOCOL_VERSION.to_string()),
            device_model: Some(std::env::consts::OS.to_string()),
            device_type: Some(DeviceType::Headless),
            fingerprint: self.fingerprint.clone(),
            port: Some(self.port),
            protocol: Some(self.protocol),
            download: self.download,
            announce,
            // Emit the v1 `announcement` flag too, so legacy peers respond.
            announcement: Some(announce),
        }
    }

    pub fn device_info(&self) -> DeviceInfo {
        DeviceInfo {
            alias: self.alias.clone(),
            version: Some(PROTOCOL_VERSION.to_string()),
            device_model: Some(std::env::consts::OS.to_string()),
            device_type: Some(DeviceType::Headless),
            fingerprint: Some(self.fingerprint.clone()),
            port: Some(self.port),
            protocol: Some(self.protocol),
            download: self.download,
        }
    }
}

fn multicast_group() -> Ipv4Addr {
    MULTICAST_ADDR.parse().unwrap()
}

/// Bind the multicast listen socket on 0.0.0.0:53317 with SO_REUSEADDR so we
/// can coexist with a running LocalSend app on the same machine.
pub fn bind_multicast_socket(port: u16) -> Result<UdpSocket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(SockProtocol::UDP))?;
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    socket.set_reuse_port(true)?;
    socket
        .bind(&SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port)).into())
        .context("bind UDP 53317")?;
    // Join the group on every IPv4 interface (mirrors the official app,
    // which registers all interfaces so discovery works on VPN + LAN).
    let group = multicast_group();
    let mut joined_any = false;
    for iface in local_ipv4_interfaces() {
        if socket.join_multicast_v4(&group, &iface).is_ok() {
            joined_any = true;
        }
    }
    if !joined_any {
        socket.join_multicast_v4(&group, &Ipv4Addr::UNSPECIFIED)?;
    }
    socket.set_multicast_loop_v4(true)?;
    socket.set_nonblocking(true)?;
    Ok(UdpSocket::from_std(socket.into())?)
}

/// Best-effort list of local IPv4 interface addresses (no extra deps:
/// parse from getifaddrs via /proc-free trick, use UDP connect probing).
pub fn local_ipv4_interfaces() -> Vec<Ipv4Addr> {
    let mut out = vec![Ipv4Addr::UNSPECIFIED];
    // Discover the primary outbound interface by "connecting" a UDP socket.
    if let Ok(s) = std::net::UdpSocket::bind("0.0.0.0:0") {
        if s.connect("224.0.0.167:53317").is_ok() {
            if let Ok(SocketAddr::V4(local)) = s.local_addr() {
                out.push(*local.ip());
            }
        }
    }
    out
}

/// Send one announcement datagram to the multicast group.
pub async fn send_announcement(me: &SelfDevice, port: u16) -> Result<()> {
    let sock = UdpSocket::bind("0.0.0.0:0").await?;
    sock.set_multicast_loop_v4(true)?;
    let msg = serde_json::to_vec(&me.announce(true))?;
    sock.send_to(&msg, (multicast_group(), port)).await?;
    Ok(())
}

/// Record a peer learned from an unauthenticated UDP multicast announce.
/// Bounded, and, to resist registry poisoning, will NOT move a known
/// fingerprint to a different address; only the authenticated /register path
/// (record_peer_trusted) may do that.
pub async fn record_peer(peers: &PeerMap, info: Announce, addr: IpAddr) {
    record_inner(peers, info, addr, false).await
}

/// Record a peer learned from the authenticated /register callback (TCP, and
/// the caller connected back to an address it chose). Trusted to update the
/// address of an existing fingerprint.
pub async fn record_peer_trusted(peers: &PeerMap, info: Announce, addr: IpAddr) {
    record_inner(peers, info, addr, true).await
}

async fn record_inner(peers: &PeerMap, info: Announce, addr: IpAddr, trusted: bool) {
    let mut map = peers.lock().await;
    match map.get(&info.fingerprint) {
        Some(existing) => {
            // Known fingerprint. An untrusted announce claiming a NEW address
            // is a poisoning attempt, ignore the move (keep the first address).
            if existing.addr != addr && !trusted {
                return;
            }
        }
        None => {
            if map.len() >= MAX_PEERS {
                return;
            }
        }
    }
    map.insert(
        info.fingerprint.clone(),
        Peer { info, addr, last_seen: Instant::now() },
    );
}

// Cap concurrent outbound /register replies so an announce storm can't spawn
// unbounded tasks or steer many outbound connections.
const MAX_INFLIGHT_REPLIES: usize = 16;

/// Listen loop: handle announcements, register back over TCP (spec §3.1),
/// fall back to a UDP reply if TCP fails. Replies are dispatched to detached,
/// bounded tasks so a slow/black-holed peer can't stall discovery.
pub async fn listen_loop(
    sock: Arc<UdpSocket>,
    me: SelfDevice,
    peers: PeerMap,
    http: reqwest::Client,
    group_port: u16,
) {
    let reply_sem = Arc::new(tokio::sync::Semaphore::new(MAX_INFLIGHT_REPLIES));
    let mut buf = vec![0u8; 64 * 1024];
    let mut err_logged = false;
    loop {
        let (n, from) = match sock.recv_from(&mut buf).await {
            Ok(v) => {
                err_logged = false;
                v
            }
            Err(e) => {
                // Don't hot-spin on a persistently broken socket.
                if !err_logged {
                    eprintln!("[lsq] discovery recv error: {e} (backing off)");
                    err_logged = true;
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
                continue;
            }
        };
        // Malformed datagrams are silently ignored (edge case: UDP garbage).
        let Ok(ann) = serde_json::from_slice::<Announce>(&buf[..n]) else {
            continue;
        };
        if ann.fingerprint == me.fingerprint {
            continue; // self-discovery, spec §2
        }
        let should_reply = ann.should_reply();
        record_peer(&peers, ann.clone(), from.ip()).await;

        if !should_reply {
            continue;
        }
        // Bounded, non-blocking reply: acquire a permit or skip this reply.
        let Ok(permit) = reply_sem.clone().try_acquire_owned() else {
            continue;
        };
        let http = http.clone();
        let sock = sock.clone();
        let body = me.device_info();
        let reply_dto = me.announce(false);
        let peer_ip = from.ip();
        let peer_port = ann.port_or(group_port);
        let scheme = match ann.protocol_or_default() {
            Protocol::Https => "https",
            Protocol::Http => "http",
        };
        tokio::spawn(async move {
            let _permit = permit; // released on task completion
            let url = format!("{scheme}://{peer_ip}:{peer_port}{API_BASE}/register");
            let ok = http
                .post(&url)
                .json(&body)
                .timeout(Duration::from_secs(5))
                .send()
                .await
                .is_ok();
            if !ok {
                // UDP fallback goes to the shared multicast port, every member
                // listens there, whatever port their HTTP server announced.
                if let Ok(msg) = serde_json::to_vec(&reply_dto) {
                    let _ = sock.send_to(&msg, (multicast_group(), group_port)).await;
                }
            }
        });
    }
}

/// Minimal HTTP /register endpoint used during client-only discovery, so
/// peers can reply to our announcement over TCP (spec §3.1). The official
/// app always has its server running while discovering; announcing a port
/// we don't serve would make peers "reply" to whatever listens there (e.g.
/// a receiver on the same host). Returns the bound ephemeral port.
async fn spawn_register_endpoint(
    me: SelfDevice,
    peers: PeerMap,
) -> Result<(u16, tokio::task::JoinHandle<()>)> {
    use axum::{extract::ConnectInfo, routing::post, Json, Router};
    let me2 = me.clone();
    let app = Router::new().route(
        &format!("{API_BASE}/register"),
        post(
            move |ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
                  body: Option<Json<DeviceInfo>>| {
                let me = me2.clone();
                let peers = peers.clone();
                async move {
                    if let Some(Json(peer)) = body {
                        if peer.fingerprint_or_default() != me.fingerprint {
                            // Authenticated reply path → trusted address update.
                            record_peer_trusted(&peers, peer.to_announce(), addr.ip()).await;
                        }
                    }
                    let info = me.device_info();
                    Json(serde_json::json!({
                        "alias": info.alias,
                        "version": info.version,
                        "deviceModel": info.device_model,
                        "deviceType": info.device_type,
                        "fingerprint": info.fingerprint,
                        "download": info.download,
                    }))
                }
            },
        ),
    );
    let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await?;
    let bound = listener.local_addr()?.port();
    let handle = tokio::spawn(async {
        let _ = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await;
    });
    Ok((bound, handle))
}

/// Active discovery: announce, listen for replies for `wait`, return peers.
pub async fn discover(
    me: &SelfDevice,
    wait: Duration,
    identity: Option<&crate::certs::Identity>,
) -> Result<Vec<Peer>> {
    let sock = Arc::new(bind_multicast_socket(MULTICAST_PORT)?);
    let peers: PeerMap = Arc::new(Mutex::new(HashMap::new()));
    // The reply below is an HTTPS request to the peer. LocalSend 1.18+ makes
    // the client certificate mandatory whenever it is not serving its web
    // pages, so a certless client is dropped with a `CertificateRequired`
    // TLS alert and the peer never learns we exist.
    let http = crate::sender::client_with_identity(identity)?;

    // Announce the ephemeral register port (plain http) so TCP replies
    // reach us and not some other process on the default port.
    let mut me = me.clone();
    let (register_port, register_server) =
        spawn_register_endpoint(me.clone(), peers.clone()).await?;
    me.port = register_port;
    me.protocol = Protocol::Http;

    let listener = tokio::spawn(listen_loop(
        sock.clone(),
        me.clone(),
        peers.clone(),
        http,
        MULTICAST_PORT,
    ));

    // Official cadence: 3 datagrams after sleeps of 100/500/2000 ms
    // (multicast_discovery.dart) to compensate UDP loss.
    let mut elapsed = Duration::ZERO;
    for delay in [100u64, 500, 2000] {
        tokio::time::sleep(Duration::from_millis(delay)).await;
        elapsed += Duration::from_millis(delay);
        send_announcement(&me, MULTICAST_PORT).await.ok();
    }
    tokio::time::sleep(wait.saturating_sub(elapsed)).await;
    // Tear down both the listen loop and the temporary register server so
    // neither the task nor its ephemeral port leaks past discovery.
    listener.abort();
    register_server.abort();

    let map = peers.lock().await;
    let mut list: Vec<Peer> = map.values().cloned().collect();
    list.sort_by(|a, b| a.info.alias.cmp(&b.info.alias));
    Ok(list)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn me() -> SelfDevice {
        SelfDevice {
            alias: "test".into(),
            fingerprint: "self-fp".into(),
            port: 53317,
            protocol: Protocol::Https,
            download: false,
        }
    }

    #[tokio::test]
    async fn peer_registry_is_bounded() {
        let peers: PeerMap = Arc::new(Mutex::new(HashMap::new()));
        for i in 0..(MAX_PEERS + 100) {
            let mut a = me().announce(false);
            a.fingerprint = format!("fp{i}");
            record_peer(&peers, a, "10.0.0.1".parse().unwrap()).await;
        }
        assert_eq!(peers.lock().await.len(), MAX_PEERS);
    }

    #[tokio::test]
    async fn known_peer_still_updates_when_full() {
        let peers: PeerMap = Arc::new(Mutex::new(HashMap::new()));
        for i in 0..MAX_PEERS {
            let mut a = me().announce(false);
            a.fingerprint = format!("fp{i}");
            record_peer(&peers, a, "10.0.0.1".parse().unwrap()).await;
        }
        // Same address (a refresh) still updates even though the map is full.
        let mut a = me().announce(false);
        a.fingerprint = "fp5".into();
        a.alias = "updated".into();
        record_peer(&peers, a, "10.0.0.1".parse().unwrap()).await;
        assert_eq!(peers.lock().await["fp5"].info.alias, "updated");
    }

    #[tokio::test]
    async fn untrusted_announce_cannot_move_known_fingerprint() {
        // An unauthenticated announce must not repoint an existing fingerprint
        // to a new address (registry poisoning); only the trusted /register
        // path may.
        let peers: PeerMap = Arc::new(Mutex::new(HashMap::new()));
        let mut a = me().announce(false);
        a.fingerprint = "victim".into();
        record_peer(&peers, a.clone(), "10.0.0.5".parse().unwrap()).await;

        // Attacker announces the same fingerprint from a different address.
        record_peer(&peers, a.clone(), "10.0.0.9".parse().unwrap()).await;
        assert_eq!(
            peers.lock().await["victim"].addr,
            "10.0.0.5".parse::<IpAddr>().unwrap(),
            "untrusted announce must not move the address"
        );

        // The authenticated register path is allowed to update the address.
        record_peer_trusted(&peers, a, "10.0.0.7".parse().unwrap()).await;
        assert_eq!(
            peers.lock().await["victim"].addr,
            "10.0.0.7".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn self_announce_shape() {
        let a = me().announce(true);
        assert_eq!(a.version.as_deref(), Some(PROTOCOL_VERSION));
        assert_eq!(a.device_type, Some(DeviceType::Headless));
        assert!(a.announce);
        assert_eq!(a.announcement, Some(true));
        assert!(a.should_reply());
    }
}
