//! In-process local proxy used by the DNS tunnels (DNSTT, SlipStream).
//!
//! A "mixed" listener on the user's proxy address accepts SOCKS5 (CONNECT, IPv4/IPv6/domain)
//! and HTTP proxy requests (CONNECT + plain `GET http://...`) and forwards every connection
//! through an upstream:
//! - `Upstream::Ssh`:    a built-in SSH client (password / keyboard-interactive auth) that
//!                       opens `direct-tcpip` channels — the equivalent of `ssh -D`, without
//!                       needing plink/sshpass. The SSH server is reached through the tunnel's
//!                       local TCP port, so any host key is accepted (the tunnel endpoint itself
//!                       is authenticated by the tunnel's public key).
//! - `Upstream::Socks5`: a SOCKS5 server reached through the tunnel (DNSTT "socks" mode,
//!                       where the server forwards to dante on 127.0.0.1:1080).

use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use russh::client;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

/// How long the SSH handshake + authentication may take (DNS tunnels are slow).
const SSH_SETUP_TIMEOUT: Duration = Duration::from_secs(90);
/// How long opening one upstream connection may take.
const DIAL_TIMEOUT: Duration = Duration::from_secs(45);
const MAX_HTTP_HEAD: usize = 64 * 1024;

/* ───────────────────────────── target address ───────────────────────────── */

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetAddr {
    Ip(SocketAddr),
    Domain(String, u16),
}

impl TargetAddr {
    pub fn host(&self) -> String {
        match self {
            TargetAddr::Ip(a) => a.ip().to_string(),
            TargetAddr::Domain(d, _) => d.clone(),
        }
    }
    pub fn port(&self) -> u16 {
        match self {
            TargetAddr::Ip(a) => a.port(),
            TargetAddr::Domain(_, p) => *p,
        }
    }
    fn from_host_port(host: &str, port: u16) -> TargetAddr {
        match host.trim_start_matches('[').trim_end_matches(']').parse::<IpAddr>() {
            Ok(ip) => TargetAddr::Ip(SocketAddr::new(ip, port)),
            Err(_) => TargetAddr::Domain(host.to_string(), port),
        }
    }
}

impl fmt::Display for TargetAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TargetAddr::Ip(a) => write!(f, "{}", a),
            TargetAddr::Domain(d, p) => write!(f, "{}:{}", d, p),
        }
    }
}

/* ───────────────────────────── SOCKS5 protocol ───────────────────────────── */

pub const SOCKS_OK: u8 = 0x00;
pub const SOCKS_GENERAL_FAILURE: u8 = 0x01;
#[allow(dead_code)]
pub const SOCKS_NET_UNREACHABLE: u8 = 0x03;
pub const SOCKS_HOST_UNREACHABLE: u8 = 0x04;
pub const SOCKS_CONN_REFUSED: u8 = 0x05;
pub const SOCKS_CMD_NOT_SUPPORTED: u8 = 0x07;
pub const SOCKS_ATYP_NOT_SUPPORTED: u8 = 0x08;

#[derive(Debug)]
pub enum SocksError {
    Io(#[allow(dead_code)] io::Error),
    /// Protocol-level failure: answer with this REP code and close.
    Reply(u8),
}

impl From<io::Error> for SocksError {
    fn from(e: io::Error) -> Self {
        SocksError::Io(e)
    }
}

/// SOCKS5 reply with an all-zero IPv4 bind address.
pub fn socks5_reply(code: u8) -> [u8; 10] {
    [0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0]
}

/// Read the client greeting and accept "no authentication".
async fn socks5_greeting<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S) -> Result<(), SocksError> {
    let ver = s.read_u8().await?;
    if ver != 0x05 {
        return Err(SocksError::Io(io::Error::new(io::ErrorKind::InvalidData, "not SOCKS5")));
    }
    let n = s.read_u8().await? as usize;
    let mut methods = vec![0u8; n];
    s.read_exact(&mut methods).await?;
    if !methods.contains(&0x00) {
        s.write_all(&[0x05, 0xFF]).await?;
        return Err(SocksError::Io(io::Error::new(io::ErrorKind::PermissionDenied, "no acceptable SOCKS5 auth method")));
    }
    s.write_all(&[0x05, 0x00]).await?;
    Ok(())
}

/// Parse a SOCKS5 request (`VER CMD RSV ATYP DST.ADDR DST.PORT`). Only CONNECT is supported.
pub async fn read_socks5_request<R: AsyncRead + Unpin>(r: &mut R) -> Result<TargetAddr, SocksError> {
    let mut head = [0u8; 4];
    r.read_exact(&mut head).await?;
    if head[0] != 0x05 {
        return Err(SocksError::Reply(SOCKS_GENERAL_FAILURE));
    }
    let target = match head[3] {
        0x01 => {
            let mut b = [0u8; 4];
            r.read_exact(&mut b).await?;
            let port = r.read_u16().await?;
            TargetAddr::Ip(SocketAddr::new(IpAddr::from(b), port))
        }
        0x04 => {
            let mut b = [0u8; 16];
            r.read_exact(&mut b).await?;
            let port = r.read_u16().await?;
            TargetAddr::Ip(SocketAddr::new(IpAddr::from(b), port))
        }
        0x03 => {
            let len = r.read_u8().await? as usize;
            let mut b = vec![0u8; len];
            r.read_exact(&mut b).await?;
            let port = r.read_u16().await?;
            let host = String::from_utf8(b).map_err(|_| SocksError::Reply(SOCKS_GENERAL_FAILURE))?;
            if host.is_empty() {
                return Err(SocksError::Reply(SOCKS_GENERAL_FAILURE));
            }
            TargetAddr::from_host_port(&host, port)
        }
        _ => return Err(SocksError::Reply(SOCKS_ATYP_NOT_SUPPORTED)),
    };
    if head[1] != 0x01 {
        // BIND / UDP ASSOCIATE cannot be carried over SSH direct-tcpip channels
        return Err(SocksError::Reply(SOCKS_CMD_NOT_SUPPORTED));
    }
    Ok(target)
}

/// Encode a SOCKS5 CONNECT request for `target`.
pub fn encode_socks5_connect(target: &TargetAddr) -> Vec<u8> {
    let mut req = vec![0x05, 0x01, 0x00];
    match target {
        TargetAddr::Ip(SocketAddr::V4(a)) => {
            req.push(0x01);
            req.extend_from_slice(&a.ip().octets());
        }
        TargetAddr::Ip(SocketAddr::V6(a)) => {
            req.push(0x04);
            req.extend_from_slice(&a.ip().octets());
        }
        TargetAddr::Domain(d, _) => {
            let b = d.as_bytes();
            req.push(0x03);
            req.push(b.len().min(255) as u8);
            req.extend_from_slice(&b[..b.len().min(255)]);
        }
    }
    req.extend_from_slice(&target.port().to_be_bytes());
    req
}

/// Act as a SOCKS5 client on `s` (no auth) and CONNECT to `target`.
async fn socks5_client_connect<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S, target: &TargetAddr) -> Result<(), DialError> {
    s.write_all(&[0x05, 0x01, 0x00]).await.map_err(DialError::io)?;
    let mut resp = [0u8; 2];
    s.read_exact(&mut resp).await.map_err(DialError::io)?;
    if resp != [0x05, 0x00] {
        return Err(DialError::Other("upstream SOCKS5 server refused the no-auth method".into()));
    }
    s.write_all(&encode_socks5_connect(target)).await.map_err(DialError::io)?;
    let mut head = [0u8; 4];
    s.read_exact(&mut head).await.map_err(DialError::io)?;
    let skip = match head[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => s.read_u8().await.map_err(DialError::io)? as usize,
        _ => return Err(DialError::Other("bad upstream SOCKS5 reply".into())),
    };
    let mut rest = vec![0u8; skip + 2];
    s.read_exact(&mut rest).await.map_err(DialError::io)?;
    if head[1] != SOCKS_OK {
        return Err(DialError::Socks(head[1]));
    }
    Ok(())
}

/* ───────────────────────────── HTTP proxy protocol ───────────────────────────── */

#[derive(Debug, PartialEq, Eq)]
pub struct HttpProxyRequest {
    pub target: TargetAddr,
    /// `CONNECT` tunnel (reply 200 then relay) vs. a forwarded plain-HTTP request.
    pub connect: bool,
    /// For plain HTTP: the request head rewritten to origin-form (sent upstream as-is).
    pub upstream_head: Vec<u8>,
}

/// Split "host:port" / "[v6]:port" / "host" into a target.
pub fn parse_authority(auth: &str, default_port: u16) -> Option<TargetAddr> {
    let auth = auth.trim();
    if auth.is_empty() {
        return None;
    }
    if let Some(rest) = auth.strip_prefix('[') {
        let (host, after) = rest.split_once(']')?;
        let port = match after.strip_prefix(':') {
            Some(p) => p.parse().ok()?,
            None if after.is_empty() => default_port,
            None => return None,
        };
        return Some(TargetAddr::from_host_port(host, port));
    }
    match auth.rsplit_once(':') {
        // A bare IPv6 address without brackets has several ':' — treat it as host only
        Some((h, p)) if !h.contains(':') => Some(TargetAddr::from_host_port(h, p.parse().ok()?)),
        _ => Some(TargetAddr::from_host_port(auth, default_port)),
    }
}

/// Parse an HTTP proxy request head (everything up to and including the blank line).
pub fn parse_http_proxy_request(head: &[u8]) -> Result<HttpProxyRequest, String> {
    let text = std::str::from_utf8(head).map_err(|_| "request head is not UTF-8".to_string())?;
    let mut lines = text.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let (method, uri, version) = match (parts.next(), parts.next(), parts.next()) {
        (Some(m), Some(u), Some(v)) => (m, u, v),
        _ => return Err(format!("malformed request line: {:?}", request_line)),
    };
    let headers: Vec<&str> = lines.filter(|l| !l.is_empty()).collect();

    if method.eq_ignore_ascii_case("CONNECT") {
        let target = parse_authority(uri, 443).ok_or_else(|| format!("bad CONNECT target {:?}", uri))?;
        return Ok(HttpProxyRequest { target, connect: true, upstream_head: Vec::new() });
    }

    // Absolute-form "http://host[:port]/path" (what browsers send to a proxy);
    // fall back to the Host header for origin-form requests.
    let (authority, path) = if uri.len() > 7 && uri[..7].eq_ignore_ascii_case("http://") {
        let rest = &uri[7..];
        let idx = rest.find(|c| c == '/' || c == '?').unwrap_or(rest.len());
        let path = &rest[idx..];
        (rest[..idx].to_string(), if path.is_empty() { "/".to_string() } else if path.starts_with('?') { format!("/{}", path) } else { path.to_string() })
    } else if uri.starts_with('/') {
        let host = headers
            .iter()
            .find_map(|h| h.split_once(':').filter(|(k, _)| k.trim().eq_ignore_ascii_case("host")).map(|(_, v)| v.trim().to_string()))
            .ok_or_else(|| "request without a Host".to_string())?;
        (host, uri.to_string())
    } else {
        return Err(format!("unsupported request target {:?}", uri));
    };
    // Strip userinfo ("user:pass@host")
    let authority = authority.rsplit('@').next().unwrap_or("").to_string();
    let target = parse_authority(&authority, 80).ok_or_else(|| format!("bad request target {:?}", uri))?;

    let mut out = format!("{} {} {}\r\n", method, path, version);
    for h in headers {
        let name = h.split(':').next().unwrap_or("").trim().to_ascii_lowercase();
        if matches!(name.as_str(), "proxy-connection" | "proxy-authorization" | "connection" | "keep-alive") {
            continue;
        }
        out.push_str(h);
        out.push_str("\r\n");
    }
    // One upstream connection per request keeps routing correct for keep-alive clients
    out.push_str("Connection: close\r\n\r\n");
    Ok(HttpProxyRequest { target, connect: false, upstream_head: out.into_bytes() })
}

/// Read until the end of the HTTP head; returns (head, bytes read past the head).
async fn read_http_head<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let mut buf = Vec::with_capacity(2048);
    let mut chunk = [0u8; 4096];
    loop {
        let n = r.read(&mut chunk).await?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "connection closed before the request head ended"));
        }
        let search_from = buf.len().saturating_sub(3);
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = buf[search_from..].windows(4).position(|w| w == b"\r\n\r\n") {
            let end = search_from + pos + 4;
            let rest = buf.split_off(end);
            return Ok((buf, rest));
        }
        if buf.len() > MAX_HTTP_HEAD {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "request head too large"));
        }
    }
}

/* ───────────────────────────── upstream dialing ───────────────────────────── */

#[derive(Debug)]
pub enum DialError {
    Socks(u8),
    Other(String),
}

impl DialError {
    fn io(e: io::Error) -> DialError {
        DialError::Other(e.to_string())
    }
    fn socks_code(&self) -> u8 {
        match self {
            DialError::Socks(c) => *c,
            DialError::Other(_) => SOCKS_GENERAL_FAILURE,
        }
    }
}

impl fmt::Display for DialError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DialError::Socks(c) => write!(f, "upstream SOCKS5 error 0x{:02x}", c),
            DialError::Other(s) => write!(f, "{}", s),
        }
    }
}

trait Duplex: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Duplex for T {}
type BoxedStream = Box<dyn Duplex>;

pub enum Upstream {
    /// SSH server reachable at `server` (the tunnel's local TCP port).
    Ssh { server: SocketAddr, user: String, password: String },
    /// SOCKS5 server reachable at `server` (the tunnel's local TCP port).
    Socks5 { server: SocketAddr },
}

#[derive(Clone)]
enum Dialer {
    Ssh(Arc<client::Handle<SshHandler>>),
    Socks5(SocketAddr),
    #[cfg(test)]
    Direct,
}

impl Dialer {
    async fn dial(&self, target: &TargetAddr) -> Result<BoxedStream, DialError> {
        let fut = async {
            match self {
                Dialer::Ssh(handle) => {
                    let ch = handle
                        .channel_open_direct_tcpip(target.host(), target.port() as u32, "127.0.0.1", 0)
                        .await
                        .map_err(|e| match e {
                            russh::Error::ChannelOpenFailure(russh::ChannelOpenFailure::ConnectFailed) => DialError::Socks(SOCKS_CONN_REFUSED),
                            russh::Error::ChannelOpenFailure(russh::ChannelOpenFailure::AdministrativelyProhibited) => {
                                DialError::Other("SSH server refused port forwarding (AllowTcpForwarding)".into())
                            }
                            russh::Error::ChannelOpenFailure(_) => DialError::Socks(SOCKS_HOST_UNREACHABLE),
                            other => DialError::Other(format!("SSH channel error: {}", other)),
                        })?;
                    Ok(Box::new(ch.into_stream()) as BoxedStream)
                }
                Dialer::Socks5(server) => {
                    let mut s = TcpStream::connect(server).await.map_err(DialError::io)?;
                    let _ = s.set_nodelay(true);
                    socks5_client_connect(&mut s, target).await?;
                    Ok(Box::new(s) as BoxedStream)
                }
                #[cfg(test)]
                Dialer::Direct => {
                    let s = match target {
                        TargetAddr::Ip(a) => TcpStream::connect(a).await,
                        TargetAddr::Domain(d, p) => TcpStream::connect((d.as_str(), *p)).await,
                    }
                    .map_err(|e| match e.kind() {
                        io::ErrorKind::ConnectionRefused => DialError::Socks(SOCKS_CONN_REFUSED),
                        _ => DialError::Socks(SOCKS_NET_UNREACHABLE),
                    })?;
                    Ok(Box::new(s) as BoxedStream)
                }
            }
        };
        tokio::time::timeout(DIAL_TIMEOUT, fut)
            .await
            .unwrap_or_else(|_| Err(DialError::Socks(SOCKS_HOST_UNREACHABLE)))
    }
}

/* ───────────────────────────── SSH client ───────────────────────────── */

struct SshHandler {
    closed: watch::Sender<bool>,
}

#[async_trait::async_trait]
impl client::Handler for SshHandler {
    type Error = russh::Error;

    async fn check_server_key(&mut self, _key: &russh::keys::ssh_key::PublicKey) -> Result<bool, Self::Error> {
        // The SSH server is only reachable through the authenticated DNS tunnel.
        Ok(true)
    }

    async fn disconnected(&mut self, reason: client::DisconnectReason<Self::Error>) -> Result<(), Self::Error> {
        let _ = self.closed.send(true);
        match reason {
            client::DisconnectReason::ReceivedDisconnect(_) => Ok(()),
            client::DisconnectReason::Error(e) => Err(e),
        }
    }
}

async fn ssh_connect(
    server: SocketAddr,
    user: &str,
    password: &str,
) -> Result<(client::Handle<SshHandler>, watch::Receiver<bool>), String> {
    let config = Arc::new(client::Config {
        keepalive_interval: Some(Duration::from_secs(30)),
        keepalive_max: 4,
        inactivity_timeout: None,
        ..Default::default()
    });
    let (closed_tx, closed_rx) = watch::channel(false);
    let mut handle = client::connect(config, server, SshHandler { closed: closed_tx })
        .await
        .map_err(|e| format!("SSH handshake through the tunnel failed: {}", e))?;

    let mut ok = handle
        .authenticate_password(user, password)
        .await
        .map_err(|e| format!("SSH authentication error: {}", e))?;
    if !ok {
        // Some servers only enable keyboard-interactive; answer every prompt with the password.
        if let Ok(mut resp) = handle.authenticate_keyboard_interactive_start(user, None).await {
            for _ in 0..5 {
                match resp {
                    client::KeyboardInteractiveAuthResponse::Success => {
                        ok = true;
                        break;
                    }
                    client::KeyboardInteractiveAuthResponse::Failure => break,
                    client::KeyboardInteractiveAuthResponse::InfoRequest { ref prompts, .. } => {
                        let answers = prompts.iter().map(|_| password.to_string()).collect();
                        match handle.authenticate_keyboard_interactive_respond(answers).await {
                            Ok(r) => resp = r,
                            Err(_) => break,
                        }
                    }
                }
            }
        }
    }
    if !ok {
        return Err(format!("SSH authentication failed for user '{}' (wrong password?)", user));
    }
    Ok((handle, closed_rx))
}

/* ───────────────────────────── server ───────────────────────────── */

/// Running local proxy; `stop()` shuts it down (and with it the SSH session).
pub struct ProxyHandle {
    shutdown: watch::Sender<bool>,
}

impl ProxyHandle {
    pub fn stop(&self) {
        let _ = self.shutdown.send(true);
    }
}

fn log(logs: &Option<PathBuf>, level: &str, msg: &str) {
    if let Some(p) = logs {
        let _ = crate::append_log(p, level, &format!("[Tunnel] {}", msg));
    }
}

/// Bind `listen`, establish the upstream (SSH login / SOCKS5 probe) and start serving.
/// `on_exit` runs (on a blocking thread) once the proxy stops for any reason, with a reason text.
pub async fn start(
    listen_host: &str,
    listen_port: u16,
    upstream: Upstream,
    logs: Option<PathBuf>,
    on_exit: Box<dyn FnOnce(String) + Send + 'static>,
) -> Result<ProxyHandle, String> {
    let listener = TcpListener::bind((listen_host, listen_port))
        .await
        .map_err(|e| format!("cannot listen on {}:{}: {} (is the port already in use?)", listen_host, listen_port, e))?;

    let (dialer, ssh_closed) = match upstream {
        Upstream::Ssh { server, user, password } => {
            log(&logs, "info", &format!("Connecting SSH to {} as '{}' through the tunnel...", server, user));
            let (handle, closed) = tokio::time::timeout(SSH_SETUP_TIMEOUT, ssh_connect(server, &user, &password))
                .await
                .map_err(|_| format!("SSH login through the tunnel timed out after {}s — the DNS tunnel is not passing traffic (check the domain/NS records, public key and resolver)", SSH_SETUP_TIMEOUT.as_secs()))??;
            log(&logs, "info", "SSH session authenticated");
            (Dialer::Ssh(Arc::new(handle)), Some(closed))
        }
        Upstream::Socks5 { server } => {
            log(&logs, "info", &format!("Checking the SOCKS5 server through the tunnel ({})...", server));
            let probe = async {
                let mut s = TcpStream::connect(server).await?;
                s.write_all(&[0x05, 0x01, 0x00]).await?;
                let mut r = [0u8; 2];
                s.read_exact(&mut r).await?;
                if r != [0x05, 0x00] {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "unexpected SOCKS5 greeting reply"));
                }
                Ok(())
            };
            tokio::time::timeout(SSH_SETUP_TIMEOUT, probe)
                .await
                .map_err(|_| "the SOCKS server behind the tunnel did not answer — the DNS tunnel is not passing traffic".to_string())?
                .map_err(|e| format!("SOCKS5 server behind the tunnel is not usable: {}", e))?;
            log(&logs, "info", "Upstream SOCKS5 server is reachable");
            (Dialer::Socks5(server), None)
        }
    };

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    tokio::spawn(async move {
        let reason = serve(listener, dialer.clone(), shutdown_rx, ssh_closed, logs.clone()).await;
        if let Dialer::Ssh(h) = &dialer {
            let _ = tokio::time::timeout(
                Duration::from_secs(2),
                h.disconnect(russh::Disconnect::ByApplication, "bye", "en"),
            )
            .await;
        }
        log(&logs, "warn", &format!("Local proxy stopped: {}", reason));
        let _ = tokio::task::spawn_blocking(move || on_exit(reason)).await;
    });
    Ok(ProxyHandle { shutdown: shutdown_tx })
}

/// Accept loop; returns why it stopped.
async fn serve(
    listener: TcpListener,
    dialer: Dialer,
    mut shutdown: watch::Receiver<bool>,
    mut ssh_closed: Option<watch::Receiver<bool>>,
    logs: Option<PathBuf>,
) -> String {
    let mut tick = tokio::time::interval(Duration::from_secs(2));
    loop {
        tokio::select! {
            _ = shutdown.changed() => return "stopped".into(),
            _ = async {
                match ssh_closed.as_mut() {
                    Some(rx) => { let _ = rx.changed().await; }
                    None => std::future::pending::<()>().await,
                }
            } => return "SSH session closed".into(),
            _ = tick.tick() => {
                if let Dialer::Ssh(h) = &dialer {
                    if h.is_closed() {
                        return "SSH session closed".into();
                    }
                }
            }
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, _)) => {
                        let _ = stream.set_nodelay(true);
                        let dialer = dialer.clone();
                        let mut stop = shutdown.clone();
                        let logs = logs.clone();
                        tokio::spawn(async move {
                            tokio::select! {
                                r = handle_client(stream, &dialer) => {
                                    if let Err(e) = r {
                                        log(&logs, "warn", &e);
                                    }
                                }
                                _ = stop.changed() => {}
                            }
                        });
                    }
                    Err(e) => {
                        log(&logs, "warn", &format!("accept failed: {}", e));
                        tokio::time::sleep(Duration::from_millis(200)).await;
                    }
                }
            }
        }
    }
}

/// Serve one client: SOCKS5 or HTTP, detected from the first byte.
async fn handle_client(mut inbound: TcpStream, dialer: &Dialer) -> Result<(), String> {
    let mut first = [0u8; 1];
    let n = inbound.peek(&mut first).await.map_err(|e| e.to_string())?;
    if n == 0 {
        return Ok(());
    }
    match first[0] {
        0x05 => {
            let target = match socks5_greeting(&mut inbound).await {
                Ok(()) => read_socks5_request(&mut inbound).await,
                Err(e) => Err(e),
            };
            let target = match target {
                Ok(t) => t,
                Err(SocksError::Reply(code)) => {
                    let _ = inbound.write_all(&socks5_reply(code)).await;
                    return Ok(());
                }
                Err(SocksError::Io(_)) => return Ok(()),
            };
            match dialer.dial(&target).await {
                Ok(mut upstream) => {
                    inbound.write_all(&socks5_reply(SOCKS_OK)).await.map_err(|e| e.to_string())?;
                    let _ = tokio::io::copy_bidirectional(&mut inbound, &mut upstream).await;
                    Ok(())
                }
                Err(e) => {
                    let _ = inbound.write_all(&socks5_reply(e.socks_code())).await;
                    Err(format!("SOCKS5 CONNECT {} failed: {}", target, e))
                }
            }
        }
        0x04 => Ok(()), // SOCKS4 is not supported
        _ => {
            let (head, rest) = match read_http_head(&mut inbound).await {
                Ok(v) => v,
                Err(_) => return Ok(()),
            };
            let req = match parse_http_proxy_request(&head) {
                Ok(r) => r,
                Err(e) => {
                    let _ = inbound.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await;
                    return Err(format!("HTTP proxy: {}", e));
                }
            };
            match dialer.dial(&req.target).await {
                Ok(mut upstream) => {
                    if req.connect {
                        inbound.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await.map_err(|e| e.to_string())?;
                    } else {
                        upstream.write_all(&req.upstream_head).await.map_err(|e| e.to_string())?;
                    }
                    if !rest.is_empty() {
                        upstream.write_all(&rest).await.map_err(|e| e.to_string())?;
                    }
                    let _ = tokio::io::copy_bidirectional(&mut inbound, &mut upstream).await;
                    Ok(())
                }
                Err(e) => {
                    let _ = inbound.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await;
                    Err(format!("HTTP proxy to {} failed: {}", req.target, e))
                }
            }
        }
    }
}

/* ───────────────────────────── tests ───────────────────────────── */

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[tokio::test]
    async fn socks5_request_ipv4() {
        let mut data: &[u8] = &[5, 1, 0, 1, 93, 184, 216, 34, 0x01, 0xBB];
        let t = read_socks5_request(&mut data).await.unwrap();
        assert_eq!(t, TargetAddr::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 443)));
    }

    #[tokio::test]
    async fn socks5_request_ipv6() {
        let mut v = vec![5, 1, 0, 4];
        v.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        v.extend_from_slice(&[0, 80]);
        let mut data: &[u8] = &v;
        let t = read_socks5_request(&mut data).await.unwrap();
        assert_eq!(t, TargetAddr::Ip(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 80)));
        assert_eq!(t.to_string(), "[::1]:80");
    }

    #[tokio::test]
    async fn socks5_request_domain_and_errors() {
        let mut v = vec![5, 1, 0, 3, 11];
        v.extend_from_slice(b"example.com");
        v.extend_from_slice(&[0x1F, 0x90]);
        let mut data: &[u8] = &v;
        assert_eq!(read_socks5_request(&mut data).await.unwrap(), TargetAddr::Domain("example.com".into(), 8080));

        // UDP ASSOCIATE -> command not supported
        let mut data: &[u8] = &[5, 3, 0, 1, 0, 0, 0, 0, 0, 0];
        assert!(matches!(read_socks5_request(&mut data).await, Err(SocksError::Reply(SOCKS_CMD_NOT_SUPPORTED))));
        // unknown address type
        let mut data: &[u8] = &[5, 1, 0, 9];
        assert!(matches!(read_socks5_request(&mut data).await, Err(SocksError::Reply(SOCKS_ATYP_NOT_SUPPORTED))));
        // truncated
        let mut data: &[u8] = &[5, 1, 0, 1, 1, 2];
        assert!(matches!(read_socks5_request(&mut data).await, Err(SocksError::Io(_))));
    }

    #[test]
    fn socks5_connect_encoding_roundtrip() {
        let t = TargetAddr::Domain("a.b".into(), 443);
        assert_eq!(encode_socks5_connect(&t), vec![5, 1, 0, 3, 3, b'a', b'.', b'b', 1, 0xBB]);
    }

    #[test]
    fn authority_parsing() {
        assert_eq!(parse_authority("example.com:443", 80), Some(TargetAddr::Domain("example.com".into(), 443)));
        assert_eq!(parse_authority("example.com", 80), Some(TargetAddr::Domain("example.com".into(), 80)));
        assert_eq!(parse_authority("[::1]:8443", 80), Some(TargetAddr::Ip("[::1]:8443".parse().unwrap())));
        assert_eq!(parse_authority("1.2.3.4:5", 80), Some(TargetAddr::Ip("1.2.3.4:5".parse().unwrap())));
        assert_eq!(parse_authority("host:notaport", 80), None);
    }

    #[test]
    fn http_request_rewrite() {
        let head = b"GET http://example.com:8080/a?b=1 HTTP/1.1\r\nHost: example.com:8080\r\nProxy-Connection: keep-alive\r\nAccept: */*\r\n\r\n";
        let r = parse_http_proxy_request(head).unwrap();
        assert!(!r.connect);
        assert_eq!(r.target, TargetAddr::Domain("example.com".into(), 8080));
        assert_eq!(
            String::from_utf8(r.upstream_head).unwrap(),
            "GET /a?b=1 HTTP/1.1\r\nHost: example.com:8080\r\nAccept: */*\r\nConnection: close\r\n\r\n"
        );
        let c = parse_http_proxy_request(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n").unwrap();
        assert!(c.connect);
        assert_eq!(c.target, TargetAddr::Domain("example.com".into(), 443));
        assert!(parse_http_proxy_request(b"garbage\r\n\r\n").is_err());
    }

    /// End-to-end over loopback only: SOCKS5 and HTTP CONNECT through the mixed listener.
    #[tokio::test]
    async fn mixed_listener_loopback() {
        // Echo server
        let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = echo.accept().await.unwrap();
                tokio::spawn(async move {
                    let (mut r, mut w) = s.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let (_tx, rx) = watch::channel(false);
        tokio::spawn(serve(listener, Dialer::Direct, rx, None, None));

        // SOCKS5
        let mut s = TcpStream::connect(proxy_addr).await.unwrap();
        s.write_all(&[5, 1, 0]).await.unwrap();
        let mut g = [0u8; 2];
        s.read_exact(&mut g).await.unwrap();
        assert_eq!(g, [5, 0]);
        s.write_all(&encode_socks5_connect(&TargetAddr::Ip(echo_addr))).await.unwrap();
        let mut rep = [0u8; 10];
        s.read_exact(&mut rep).await.unwrap();
        assert_eq!(rep[1], SOCKS_OK);
        s.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");

        // HTTP CONNECT
        let mut h = TcpStream::connect(proxy_addr).await.unwrap();
        h.write_all(format!("CONNECT {} HTTP/1.1\r\nHost: x\r\n\r\n", echo_addr).as_bytes()).await.unwrap();
        let mut resp = [0u8; 39];
        h.read_exact(&mut resp).await.unwrap();
        assert!(resp.starts_with(b"HTTP/1.1 200"));
        h.write_all(b"pong").await.unwrap();
        h.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");

        // Refused target -> SOCKS reply 0x05
        let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let closed_addr = closed.local_addr().unwrap();
        drop(closed);
        let mut s = TcpStream::connect(proxy_addr).await.unwrap();
        s.write_all(&[5, 1, 0]).await.unwrap();
        s.read_exact(&mut g).await.unwrap();
        s.write_all(&encode_socks5_connect(&TargetAddr::Ip(closed_addr))).await.unwrap();
        s.read_exact(&mut rep).await.unwrap();
        assert_eq!(rep[1], SOCKS_CONN_REFUSED);
    }
}
