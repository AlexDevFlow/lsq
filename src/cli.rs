//! CLI definitions and command orchestration.

use crate::certs;
use crate::discovery::{self, Peer, SelfDevice};
use crate::proto::*;
use crate::receiver::{self, AppState, ReceiverConfig};
use crate::share;
use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

#[derive(Parser)]
#[command(
    name = "lsq",
    version,
    about = "Command-line client for LocalSend: send and receive files over your local network"
)]
pub struct Cli {
    /// Device alias shown to peers (default: "<hostname> (lsq)")
    #[arg(long, global = true)]
    alias: Option<String>,
    /// Port for server and discovery
    #[arg(long, global = true, default_value_t = DEFAULT_PORT)]
    port: u16,
    /// Suppress progress output (for scripts)
    #[arg(short, long, global = true)]
    quiet: bool,
    /// Use a throwaway identity instead of the saved one in the config dir
    #[arg(long, global = true)]
    ephemeral: bool,
    #[command(subcommand)]
    command: Command,
}

/// Where the persistent identity (cert.pem/key.pem) is kept.
fn config_dir() -> PathBuf {
    if let Some(d) = std::env::var_os("LSQ_CONFIG_DIR") {
        return PathBuf::from(d);
    }
    if let Some(d) = std::env::var_os("XDG_CONFIG_HOME") {
        return PathBuf::from(d).join("lsq");
    }
    if let Some(h) = std::env::var_os("HOME") {
        return PathBuf::from(h).join(".config").join("lsq");
    }
    PathBuf::from(".lsq")
}

fn identity(ephemeral: bool) -> Result<certs::Identity> {
    if ephemeral {
        certs::generate_identity("")
    } else {
        certs::load_or_create_identity(&config_dir())
    }
}

#[derive(Subcommand)]
enum Command {
    /// Discover LocalSend peers on the network
    List {
        /// Seconds to wait for replies
        #[arg(long, default_value_t = 3)]
        wait: u64,
        /// Print machine-readable JSON
        #[arg(long)]
        json: bool,
    },
    /// Send files or directories to a peer
    Send {
        /// Files or directories
        #[arg(required = true)]
        paths: Vec<PathBuf>,
        /// Target: alias substring, fingerprint prefix, or IP[:port]
        #[arg(long, short)]
        to: Option<String>,
        /// PIN if the receiver requires one
        #[arg(long)]
        pin: Option<String>,
        /// Seconds to wait for discovery
        #[arg(long, default_value_t = 3)]
        wait: u64,
    },
    /// Receive files (interactive accept unless --yes)
    Receive {
        /// Destination directory
        #[arg(long, short, default_value = ".")]
        dest: PathBuf,
        /// Auto-accept all transfers (daemon-friendly)
        #[arg(long, short = 'y')]
        yes: bool,
        /// Require this PIN from senders
        #[arg(long)]
        pin: Option<String>,
        /// Use plain HTTP instead of HTTPS
        #[arg(long)]
        http: bool,
        /// Reject transfers whose declared total exceeds this size (e.g. 2G, 500M)
        #[arg(long, value_parser = parse_size)]
        max_size: Option<u64>,
    },
    /// Share files for download by browsers and other clients (Download API)
    Share {
        /// Files or directories to offer
        #[arg(required = true)]
        paths: Vec<PathBuf>,
        /// Require this PIN from downloaders
        #[arg(long)]
        pin: Option<String>,
    },
    /// Download files a peer is sharing (Download API)
    Pull {
        /// Source: alias substring, fingerprint prefix, IP[:port], or URL
        from: Option<String>,
        /// Destination directory
        #[arg(long, short, default_value = ".")]
        dest: PathBuf,
        /// PIN if the peer requires one
        #[arg(long)]
        pin: Option<String>,
        /// Seconds to wait for discovery
        #[arg(long, default_value_t = 3)]
        wait: u64,
        /// Refuse if the declared total exceeds this size (e.g. 2G, 500M)
        #[arg(long, value_parser = parse_size)]
        max_size: Option<u64>,
    },
    /// Show this device's identity
    Info,
}

/// Parse a human size like "2G", "500M", "1024" (bytes) into a byte count.
fn parse_size(s: &str) -> std::result::Result<u64, String> {
    let s = s.trim();
    let (num, mult) = match s.chars().last() {
        Some('K' | 'k') => (&s[..s.len() - 1], 1024u64),
        Some('M' | 'm') => (&s[..s.len() - 1], 1024 * 1024),
        Some('G' | 'g') => (&s[..s.len() - 1], 1024 * 1024 * 1024),
        Some('T' | 't') => (&s[..s.len() - 1], 1024u64.pow(4)),
        _ => (s, 1),
    };
    num.trim()
        .parse::<u64>()
        .map_err(|_| format!("invalid size: {s}"))?
        .checked_mul(mult)
        .ok_or_else(|| format!("size too large: {s}"))
}

fn default_alias() -> String {
    let host = hostname::get()
        .ok()
        .map(|h| h.to_string_lossy().into_owned())
        .unwrap_or_else(|| "unknown".into());
    format!("{host} (lsq)")
}

pub async fn run() -> Result<()> {
    // rustls needs a process-level default crypto provider.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cli = Cli::parse();
    let alias = cli.alias.clone().unwrap_or_else(default_alias);

    let eph = cli.ephemeral;
    match cli.command {
        Command::List { wait, json } => cmd_list(alias, cli.port, wait, json, eph).await,
        Command::Send { paths, to, pin, wait } => {
            cmd_send(alias, cli.port, paths, to, pin, wait, cli.quiet, eph).await
        }
        Command::Receive { dest, yes, pin, http, max_size } => {
            cmd_receive(alias, cli.port, dest, yes, pin, http, max_size, cli.quiet, eph).await
        }
        Command::Share { paths, pin } => {
            cmd_share(alias, cli.port, paths, pin, cli.quiet, eph).await
        }
        Command::Pull { from, dest, pin, wait, max_size } => {
            cmd_pull(alias, cli.port, from, dest, pin, wait, max_size, cli.quiet, eph).await
        }
        Command::Info => cmd_info(alias, eph),
    }
}

fn cmd_info(alias: String, eph: bool) -> Result<()> {
    let id = identity(eph)?;
    println!("alias:       {alias}");
    println!("device type: headless");
    println!("protocol:    {PROTOCOL_VERSION}");
    println!("port:        {DEFAULT_PORT}");
    if eph {
        println!("fingerprint: {} (ephemeral)", id.fingerprint);
    } else {
        println!("fingerprint: {}", id.fingerprint);
        println!("identity:    {}", config_dir().display());
    }
    Ok(())
}

async fn cmd_list(alias: String, port: u16, wait: u64, json: bool, eph: bool) -> Result<()> {
    let identity = identity(eph)?;
    let me = SelfDevice {
        alias,
        fingerprint: identity.fingerprint.clone(),
        port,
        protocol: Protocol::Https,
        download: false,
    };
    let peers = discovery::discover(&me, Duration::from_secs(wait), Some(&identity)).await?;
    if json {
        let out: Vec<_> = peers
            .iter()
            .map(|p| {
                serde_json::json!({
                    "alias": p.info.alias,
                    "ip": p.addr.to_string(),
                    "port": p.info.port,
                    "protocol": p.info.protocol,
                    "deviceType": p.info.device_type,
                    "deviceModel": p.info.device_model,
                    "fingerprint": p.info.fingerprint,
                    "download": p.info.download,
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(());
    }
    if peers.is_empty() {
        eprintln!("no peers found (is LocalSend running on the other device?)");
        return Ok(());
    }
    let mut table = comfy_table::Table::new();
    table.set_header(["Alias", "IP", "Port", "Proto", "Type", "Model", "DL"]);
    for p in &peers {
        table.add_row([
            p.info.alias.clone(),
            p.addr.to_string(),
            p.info.port_or(DEFAULT_PORT).to_string(),
            match p.info.protocol_or_default() {
                Protocol::Https => "https".into(),
                Protocol::Http => "http".into(),
            },
            format!("{:?}", p.info.device_type.unwrap_or_default()).to_lowercase(),
            p.info.device_model.clone().unwrap_or_default(),
            if p.info.download { "yes".into() } else { String::new() },
        ]);
    }
    println!("{table}");
    Ok(())
}

/// Resolve `--to` (alias substring / fingerprint prefix / IP[:port]) to a peer.
pub fn resolve_target(peers: &[Peer], to: Option<&str>) -> Result<Peer> {
    let Some(to) = to else {
        return match peers.len() {
            0 => bail!("no peers found, is the receiver running?"),
            1 => Ok(peers[0].clone()),
            n => bail!(
                "{n} peers found, pick one with --to:\n{}",
                peers
                    .iter()
                    .map(|p| format!("  {} ({})", p.info.alias, p.addr))
                    .collect::<Vec<_>>()
                    .join("\n")
            ),
        };
    };

    // IP[:port] form works without discovery hits.
    if let Ok(addr) = to.parse::<std::net::IpAddr>() {
        return Ok(synthetic_peer(addr, DEFAULT_PORT));
    }
    if let Ok(sock) = to.parse::<SocketAddr>() {
        return Ok(synthetic_peer(sock.ip(), sock.port()));
    }

    let lower = to.to_lowercase();
    let matches: Vec<&Peer> = peers
        .iter()
        .filter(|p| {
            p.info.alias.to_lowercase().contains(&lower)
                || p.info.fingerprint.to_lowercase().starts_with(&lower)
        })
        .collect();
    match matches.len() {
        0 => bail!("no peer matches \"{to}\""),
        1 => Ok(matches[0].clone()),
        _ => bail!(
            "\"{to}\" is ambiguous:\n{}",
            matches
                .iter()
                .map(|p| format!("  {} ({})", p.info.alias, p.addr))
                .collect::<Vec<_>>()
                .join("\n")
        ),
    }
}

fn synthetic_peer(addr: std::net::IpAddr, port: u16) -> Peer {
    Peer {
        info: Announce {
            alias: addr.to_string(),
            version: Some(PROTOCOL_VERSION.into()),
            device_model: None,
            device_type: None,
            fingerprint: String::new(),
            port: Some(port),
            protocol: Some(Protocol::Https),
            download: false,
            announce: false,
            announcement: None,
        },
        addr,
        last_seen: std::time::Instant::now(),
    }
}

#[allow(clippy::too_many_arguments)]
async fn cmd_send(
    alias: String,
    port: u16,
    paths: Vec<PathBuf>,
    to: Option<String>,
    pin: Option<String>,
    wait: u64,
    quiet: bool,
    eph: bool,
) -> Result<()> {
    let files = crate::sender::collect_files(&paths)?;
    let identity = identity(eph)?;
    let me = SelfDevice {
        alias,
        fingerprint: identity.fingerprint.clone(),
        port,
        protocol: Protocol::Https,
        download: false,
    };

    // Direct IP targets skip discovery entirely.
    let peer = if let Some(t) = to.as_deref() {
        if t.parse::<std::net::IpAddr>().is_ok() || t.parse::<SocketAddr>().is_ok() {
            resolve_target(&[], Some(t))?
        } else {
            let peers = discovery::discover(&me, Duration::from_secs(wait), Some(&identity)).await?;
            resolve_target(&peers, Some(t))?
        }
    } else {
        let peers = discovery::discover(&me, Duration::from_secs(wait), Some(&identity)).await?;
        resolve_target(&peers, None)?
    };

    // When targeting by IP we don't know the peer's protocol; try HTTPS
    // first, then fall back to HTTP (mirrors how the app probes).
    if !quiet {
        eprintln!(
            "sending {} file(s) to {} ({})",
            files.len(),
            peer.info.alias,
            peer.addr
        );
    }
    let outcome = match crate::sender::send_files(
        &me, &peer, files, pin.as_deref(), quiet, Some(&identity),
    )
    .await
    {
        Ok(o) => o,
        // Only fall back to plain HTTP for a synthetic IP target that we
        // couldn't even reach over HTTPS, never on a protocol rejection or a
        // mid-transfer failure, which would blindly re-send files.
        Err(e)
            if e.unreachable
                && peer.info.fingerprint.is_empty()
                && peer.info.protocol_or_default() == Protocol::Https =>
        {
            let mut p2 = peer.clone();
            p2.info.protocol = Some(Protocol::Http);
            let files = crate::sender::collect_files(&paths)?;
            crate::sender::send_files(&me, &p2, files, pin.as_deref(), quiet, Some(&identity))
                .await
                .map_err(|e2| anyhow::anyhow!("{e}; also failed over http: {e2}"))?
        }
        Err(e) => return Err(e.into()),
    };
    if !quiet {
        eprintln!(
            "done: {} sent, {} skipped by receiver",
            outcome.sent, outcome.skipped
        );
    }
    if outcome.sent == 0 && outcome.skipped > 0 {
        bail!("receiver skipped all files");
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn cmd_receive(
    alias: String,
    port: u16,
    dest: PathBuf,
    yes: bool,
    pin: Option<String>,
    http: bool,
    max_size: Option<u64>,
    quiet: bool,
    eph: bool,
) -> Result<()> {
    tokio::fs::create_dir_all(&dest)
        .await
        .with_context(|| format!("cannot create dest dir {}", dest.display()))?;

    let protocol = if http { Protocol::Http } else { Protocol::Https };
    let identity = identity(eph)?;
    let me = SelfDevice {
        alias: alias.clone(),
        fingerprint: identity.fingerprint.clone(),
        port,
        protocol,
        download: false,
    };

    let (events_tx, events_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    let peers: discovery::PeerMap = Default::default();
    let state = Arc::new(AppState {
        me: me.clone(),
        cfg: ReceiverConfig {
            dest: dest.clone(),
            accept: if yes { receiver::AcceptMode::Yes } else { receiver::AcceptMode::Prompt },
            pin,
            quiet,
            max_bytes: max_size,
        },
        session: Default::default(),
        pin_guard: Default::default(),
        peers: peers.clone(),
        events: events_tx,
    });
    let app = receiver::router(state.clone())
        .into_make_service_with_connect_info::<SocketAddr>();
    let addr: SocketAddr = ([0, 0, 0, 0], port).into();

    // HTTP(S) server
    let server = if http {
        tokio::spawn(async move {
            axum_server::bind(addr).serve(app).await.map_err(anyhow::Error::from)
        })
    } else {
        let tls = axum_server::tls_rustls::RustlsConfig::from_pem(
            identity.cert_pem.clone().into_bytes(),
            identity.key_pem.clone().into_bytes(),
        )
        .await
        .context("TLS config")?;
        tokio::spawn(async move {
            axum_server::bind_rustls(addr, tls).serve(app).await.map_err(anyhow::Error::from)
        })
    };

    // Reaper: free the session slot if a transfer is abandoned or stalls, so
    // one peer can't permanently block the receiver.
    tokio::spawn(receiver::reap_stale_sessions(state.clone()));

    announce_presence(&me, peers, Some(&identity)).await?;

    if !quiet {
        eprintln!(
            "receiving as \"{alias}\" on port {port} ({}) → {}",
            if http { "http" } else { "https" },
            dest.display()
        );
        eprintln!("waiting for transfers... (Ctrl-C to stop)");
    }

    // Event log loop; the server task ends only on error (e.g. port in use).
    serve_until_interrupted(server, events_rx, port, quiet).await
}

/// Shared tail of receive and share: log events until Ctrl-C, or surface a
/// server failure (e.g. port in use).
async fn serve_until_interrupted(
    server: tokio::task::JoinHandle<Result<()>>,
    mut events_rx: tokio::sync::mpsc::UnboundedReceiver<String>,
    port: u16,
    quiet: bool,
) -> Result<()> {
    tokio::pin!(server);
    loop {
        tokio::select! {
            Some(msg) = events_rx.recv() => {
                if !quiet { eprintln!("[lsq] {msg}"); }
            }
            res = tokio::signal::ctrl_c() => {
                res.ok();
                if !quiet { eprintln!("\nbye"); }
                return Ok(());
            }
            joined = &mut server => {
                return match joined {
                    Ok(Err(e)) => Err(e.context(format!("server failed on port {port}"))),
                    Ok(Ok(())) => Ok(()),
                    Err(e) => Err(anyhow::anyhow!("server task panicked: {e}")),
                };
            }
        }
    }
}

/// Multicast presence for a long-running server (receive/share): initial
/// announcement burst, reply loop, and periodic re-announce.
async fn announce_presence(
    me: &SelfDevice,
    peers: discovery::PeerMap,
    identity: Option<&crate::certs::Identity>,
) -> Result<()> {
    let udp = Arc::new(discovery::bind_multicast_socket(MULTICAST_PORT)?);
    // Presents our certificate: see the note in `discovery::discover`.
    let http_client = crate::sender::client_with_identity(identity)?;
    tokio::spawn(discovery::listen_loop(
        udp.clone(),
        me.clone(),
        peers,
        http_client,
        MULTICAST_PORT,
    ));
    for _ in 0..3 {
        discovery::send_announcement(me, MULTICAST_PORT).await.ok();
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    // Keep announcing so a device that opens LocalSend after us still sees us,
    // even if its own announcement never reaches this host.
    let me = me.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            discovery::send_announcement(&me, MULTICAST_PORT).await.ok();
        }
    });
    Ok(())
}

async fn cmd_share(
    alias: String,
    port: u16,
    paths: Vec<PathBuf>,
    pin: Option<String>,
    quiet: bool,
    eph: bool,
) -> Result<()> {
    let files = crate::sender::collect_files(&paths)?;
    let identity = identity(eph)?;
    // Plain HTTP: the Download API serves browsers, which reject
    // self-signed certificates (spec §5).
    let me = SelfDevice {
        alias: alias.clone(),
        fingerprint: identity.fingerprint.clone(),
        port,
        protocol: Protocol::Http,
        download: true,
    };

    let mut shared = std::collections::BTreeMap::new();
    let total: u64 = files.iter().fold(0, |a, f| a.saturating_add(f.dto.size));
    let count = files.len();
    for f in files {
        shared.insert(f.id.clone(), share::SharedFile { dto: f.dto, path: f.path });
    }

    let (events_tx, events_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    let peers: discovery::PeerMap = Default::default();
    let state = Arc::new(share::ShareState {
        me: me.clone(),
        files: shared,
        pin,
        quiet,
        sessions: Default::default(),
        pin_guard: Default::default(),
        peers: peers.clone(),
        events: events_tx,
    });
    let app = share::router(state).into_make_service_with_connect_info::<SocketAddr>();
    let addr: SocketAddr = ([0, 0, 0, 0], port).into();
    let server = tokio::spawn(async move {
        axum_server::bind(addr).serve(app).await.map_err(anyhow::Error::from)
    });

    announce_presence(&me, peers, Some(&identity)).await?;

    if !quiet {
        eprintln!("sharing {count} file(s), {total} bytes as \"{alias}\"");
        for ip in discovery::local_ipv4_interfaces() {
            if !ip.is_unspecified() {
                eprintln!("  http://{ip}:{port}");
            }
        }
        eprintln!("peers can also run: lsq pull \"{alias}\"");
        eprintln!("waiting for downloads... (Ctrl-C to stop)");
    }

    serve_until_interrupted(server, events_rx, port, quiet).await
}

#[allow(clippy::too_many_arguments)]
async fn cmd_pull(
    alias: String,
    port: u16,
    from: Option<String>,
    dest: PathBuf,
    pin: Option<String>,
    wait: u64,
    max_size: Option<u64>,
    quiet: bool,
    eph: bool,
) -> Result<()> {
    tokio::fs::create_dir_all(&dest)
        .await
        .with_context(|| format!("cannot create dest dir {}", dest.display()))?;
    let identity = identity(eph)?;

    // Full URL target: use it as-is.
    if let Some(t) = from.as_deref() {
        if t.starts_with("http://") || t.starts_with("https://") {
            let outcome =
                crate::pull::pull_files(t, &dest, pin.as_deref(), max_size, quiet, Some(&identity)).await?;
            return report_pull(outcome, &dest, quiet);
        }
    }

    // IP[:port] target: the protocol is unknown, so try HTTPS and fall back
    // to plain HTTP only if the peer never answered (mirrors send).
    if let Some(t) = from.as_deref() {
        if t.parse::<std::net::IpAddr>().is_ok() || t.parse::<SocketAddr>().is_ok() {
            let peer = resolve_target(&[], Some(t))?;
            let host = format!("{}:{}", peer.addr, peer.info.port_or(DEFAULT_PORT));
            let outcome = match crate::pull::pull_files(
                &format!("https://{host}"), &dest, pin.as_deref(), max_size, quiet, Some(&identity),
            )
            .await
            {
                Ok(o) => o,
                Err(e) if e.unreachable => {
                    crate::pull::pull_files(
                        &format!("http://{host}"), &dest, pin.as_deref(), max_size, quiet, Some(&identity),
                    )
                    .await
                    .map_err(|e2| anyhow::anyhow!("{e}; also failed over http: {e2}"))?
                }
                Err(e) => return Err(e.into()),
            };
            return report_pull(outcome, &dest, quiet);
        }
    }

    // Alias/fingerprint target (or no target): discover, keep peers that
    // announce the download flag.
    let me = SelfDevice {
        alias,
        fingerprint: identity.fingerprint.clone(),
        port,
        protocol: Protocol::Https,
        download: false,
    };
    let peers = discovery::discover(&me, Duration::from_secs(wait), Some(&identity)).await?;
    let peer = if from.is_some() {
        let p = resolve_target(&peers, from.as_deref())?;
        if !p.info.download {
            bail!("{} is not offering downloads", p.info.alias);
        }
        p
    } else {
        let offering: Vec<_> = peers.into_iter().filter(|p| p.info.download).collect();
        if offering.is_empty() {
            bail!("no peers offering downloads (run \"lsq share\" or enable the link share on the other device)");
        }
        resolve_target(&offering, None)?
    };
    if !quiet {
        eprintln!("pulling from {} ({})", peer.info.alias, peer.addr);
    }
    let base = crate::sender::base_url(&peer);
    let outcome =
        crate::pull::pull_files(&base, &dest, pin.as_deref(), max_size, quiet, Some(&identity)).await?;
    report_pull(outcome, &dest, quiet)
}

fn report_pull(outcome: crate::pull::PullOutcome, dest: &Path, quiet: bool) -> Result<()> {
    if !quiet {
        eprintln!(
            "done: {} file(s), {} bytes → {}",
            outcome.fetched,
            outcome.total_bytes,
            dest.display()
        );
    }
    Ok(())
}
