use std::sync::{Arc, Mutex};

use anyhow::Context;
use hyper::body::Bytes;
use hyper::body::Incoming;
use http_body_util::BodyExt;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tracing::{debug, warn};

use crate::cert::CaState;
use crate::registry::Ecosystem;

#[derive(Debug, Clone, Default)]
pub struct ProxyStats {
    pub connections_tunneled: usize,
    pub connections_intercepted: usize,
    pub requests_inspected: usize,
    pub versions_suppressed: Vec<SuppressedItem>,
    pub downloads_blocked: Vec<BlockedItem>,
}

#[derive(Debug, Clone)]
pub struct SuppressedItem {
    pub package: String,
    pub version: String,
}

#[derive(Debug, Clone)]
pub struct BlockedItem {
    pub package: String,
    pub version: String,
}

impl ProxyStats {
    pub fn active(&self) -> bool {
        self.connections_intercepted > 0 || self.connections_tunneled > 0
    }
}

pub struct ProxyServer {
    shutdown_tx: tokio::sync::oneshot::Sender<()>,
    pub url: String,
    pub ca_cert_pem: String,
    stats: Arc<Mutex<ProxyStats>>,
}

impl ProxyServer {
    pub async fn spawn(ecosystem: Option<Ecosystem>) -> anyhow::Result<Self> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .context("bind proxy port")?;
        let proxy_addr = listener.local_addr()?;
        let proxy_url = format!("http://{}", proxy_addr);
        debug!("proxy listening {}", proxy_url);

        let ca_state = Arc::new(Mutex::new(CaState::new()?));
        let ca_cert_pem = ca_state.lock().unwrap().ca_cert_pem().to_string();

        let stats = Arc::new(Mutex::new(ProxyStats::default()));

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(run(listener, ecosystem, ca_state, stats.clone(), shutdown_rx));

        Ok(ProxyServer {
            shutdown_tx,
            url: proxy_url,
            ca_cert_pem,
            stats,
        })
    }

    pub fn shutdown(self) {
        let _ = self.shutdown_tx.send(());
    }

    pub fn stats(&self) -> ProxyStats {
        self.stats.lock().unwrap().clone()
    }
}

async fn run(
    listener: tokio::net::TcpListener,
    ecosystem: Option<Ecosystem>,
    ca_state: Arc<Mutex<CaState>>,
    stats: Arc<Mutex<ProxyStats>>,
    mut shutdown_rx: tokio::sync::oneshot::Receiver<()>,
) -> anyhow::Result<()> {
    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                let (stream, addr) = accept_result?;
                debug!("accepted {}", addr);
                let ec = ecosystem;
                let ca = ca_state.clone();
                let st = stats.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(stream, ec, ca, st).await {
                        warn!("connection error: {:#}", e);
                    }
                });
            }
            _ = &mut shutdown_rx => return Ok(()),
        }
    }
}

async fn handle_connection(
    stream: TcpStream,
    ecosystem: Option<Ecosystem>,
    ca_state: Arc<Mutex<CaState>>,
    stats: Arc<Mutex<ProxyStats>>,
) -> anyhow::Result<()> {
    let mut reader = BufReader::new(stream);
    let mut first_line = Vec::new();
    reader.read_until(b'\n', &mut first_line).await?;
    let line = String::from_utf8_lossy(&first_line);

    if line.starts_with("CONNECT ") {
        let host_port = parse_connect_host(&line)?;
        let stream = reader.into_inner();
        handle_connect(stream, &host_port, ecosystem, ca_state, stats).await
    } else {
        handle_http(reader, first_line).await
    }
}

fn parse_connect_host(line: &str) -> anyhow::Result<String> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 2 {
        anyhow::bail!("invalid CONNECT request");
    }
    Ok(parts[1].to_string())
}

fn parse_host_port(host_port: &str) -> (String, u16) {
    let mut parts = host_port.splitn(2, ':');
    let host = parts.next().unwrap_or("localhost").to_string();
    let port: u16 = parts.next().unwrap_or("443").parse().unwrap_or(443);
    (host, port)
}

async fn handle_connect(
    client: TcpStream,
    host_port: &str,
    ecosystem: Option<Ecosystem>,
    ca_state: Arc<Mutex<CaState>>,
    stats: Arc<Mutex<ProxyStats>>,
) -> anyhow::Result<()> {
    let (host, port) = parse_host_port(host_port);

    if let Some(ec) = ecosystem {
        if ec.matches_host(&host) {
            stats.lock().unwrap().connections_intercepted += 1;
            return handle_mitm(client, host, port, ec, ca_state, stats).await;
        }
    }

    stats.lock().unwrap().connections_tunneled += 1;
    handle_tunnel(client, &host, port).await
}

async fn handle_tunnel(
    mut client: TcpStream,
    host: &str,
    port: u16,
) -> anyhow::Result<()> {
    let mut target = TcpStream::connect((host, port))
        .await
        .with_context(|| format!("connect to {}:{}", host, port))?;
    client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;

    let (mut cr, mut cw) = client.split();
    let (mut tr, mut tw) = target.split();
    tokio::select! {
        r = tokio::io::copy(&mut cr, &mut tw) => r?,
        r = tokio::io::copy(&mut tr, &mut cw) => r?,
    };
    Ok(())
}

async fn handle_mitm(
    mut client: TcpStream,
    host: String,
    port: u16,
    ecosystem: Ecosystem,
    ca_state: Arc<Mutex<CaState>>,
    stats: Arc<Mutex<ProxyStats>>,
) -> anyhow::Result<()> {
    client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;

    let acceptor = ca_state
        .lock()
        .unwrap()
        .tls_acceptor_for_host(&host)?;
    let tls_stream = acceptor.accept(client).await?;

    let io = TokioIo::new(tls_stream);
    let registry = ecosystem.registry();
    let svc = MitmService {
        host,
        port,
        registry,
        stats,
    };

    hyper::server::conn::http1::Builder::new()
        .serve_connection(io, svc)
        .await?;

    Ok(())
}

struct MitmService {
    host: String,
    port: u16,
    registry: Box<dyn crate::registry::Registry>,
    stats: Arc<Mutex<ProxyStats>>,
}

impl hyper::service::Service<hyper::Request<Incoming>> for MitmService {
    type Response = hyper::Response<http_body_util::combinators::BoxBody<Bytes, String>>;
    type Error = anyhow::Error;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn call(&self, req: hyper::Request<Incoming>) -> Self::Future {
        let host = self.host.clone();
        let port = self.port;
        let stats = self.stats.clone();

        Box::pin(async move {
            stats.lock().unwrap().requests_inspected += 1;
            let resp = forward_https(&host, port, req).await?;
            Ok(resp)
        })
    }
}

async fn forward_https(
    host: &str,
    port: u16,
    req: hyper::Request<Incoming>,
) -> anyhow::Result<hyper::Response<http_body_util::combinators::BoxBody<Bytes, String>>> {
    let target_url = format!("https://{}{}", host, req.uri());
    let uri: hyper::Uri = target_url.parse()?;

    let mut builder = hyper::Request::builder()
        .method(req.method().clone())
        .uri(&uri)
        .version(req.version());

    for (name, value) in req.headers() {
        if name == "host" {
            continue;
        }
        builder = builder.header(name.clone(), value.clone());
    }

    let forward_req = builder.body(req.into_body())?;

    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store())
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config));

    let addr = format!("{}:{}", host, port);
    let stream = TcpStream::connect(&addr).await?;
    let domain = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|e| anyhow::anyhow!("invalid domain: {}", e))?;
    let tls_stream = connector.connect(domain, stream).await?;
    let io = TokioIo::new(tls_stream);

    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            warn!("upstream conn error: {}", e);
        }
    });

    let resp = sender.send_request(forward_req).await?;
    let (parts, body) = resp.into_parts();
    let mapped = body.map_err(|e| e.to_string()).boxed();
    Ok(hyper::Response::from_parts(parts, mapped))
}

fn root_store() -> Arc<rustls::RootCertStore> {
    let mut store = rustls::RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs()
        .expect("load native certs")
    {
        store.add(cert).ok();
    }
    Arc::new(store)
}

async fn handle_http(
    mut reader: BufReader<TcpStream>,
    first_line: Vec<u8>,
) -> anyhow::Result<()> {
    let mut headers_buf = first_line;
    loop {
        let mut line = Vec::new();
        tokio::io::AsyncBufReadExt::read_until(&mut reader, b'\n', &mut line).await?;
        headers_buf.extend_from_slice(&line);
        if line == b"\r\n" || line == b"\n" || line.is_empty() {
            break;
        }
    }

    let request_str = String::from_utf8_lossy(&headers_buf);
    let first_line = request_str.lines().next().context("empty request")?;
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() < 2 {
        anyhow::bail!("malformed HTTP request");
    }
    let method = parts[0];
    let raw_url = parts[1];

    let url = url::Url::parse(raw_url).context("parse target URL")?;
    let host = url.host_str().context("missing host")?;
    let port = url.port_or_known_default().unwrap_or(80);

    let addr = format!("{}:{}", host, port);
    let mut target = TcpStream::connect(&addr).await?;

    let path = if let Some(query) = url.query() {
        format!("{}?{}", url.path(), query)
    } else {
        url.path().to_string()
    };

    let forward_req = format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        method, path, host
    );

    target.write_all(forward_req.as_bytes()).await?;

    let mut remaining = reader;
    tokio::io::copy(&mut remaining, &mut target).await.ok();

    Ok(())
}
