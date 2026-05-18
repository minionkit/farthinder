use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
    Mutex,
};

use anyhow::Context;
use http_body_util::BodyExt;
use hyper::body::Bytes;
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tracing::{debug, warn};
use url::Url;

use crate::cert::CaState;
use crate::registry::{Registry, ResponseAction};

pub struct ProxyServer {
    shutdown_tx: tokio::sync::oneshot::Sender<()>,
    pub url: String,
    pub ca_cert_pem: String,
    tunneled: Arc<AtomicUsize>,
}

impl ProxyServer {
    pub async fn spawn(registry: Arc<dyn Registry>) -> anyhow::Result<Self> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .context("bind proxy port")?;
        let proxy_addr = listener.local_addr()?;
        let proxy_url = format!("http://{}", proxy_addr);
        debug!("proxy listening {}", proxy_url);

        let ca_state = Arc::new(Mutex::new(CaState::new()?));
        let ca_cert_pem = ca_state.lock().unwrap().ca_cert_pem().to_string();
        let tunneled = Arc::new(AtomicUsize::new(0));

        let core = ProxyCore {
            registry,
            ca_state,
            tunneled: tunneled.clone(),
        };

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(core.accept_loop(listener, shutdown_rx));

        Ok(ProxyServer {
            shutdown_tx,
            url: proxy_url,
            ca_cert_pem,
            tunneled,
        })
    }

    pub fn shutdown(self) {
        let _ = self.shutdown_tx.send(());
    }

    pub fn port(&self) -> u16 {
        self.url
            .rsplit(':')
            .next()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0)
    }

    pub fn tunneled(&self) -> usize {
        self.tunneled.load(Ordering::Relaxed)
    }
}

struct ProxyCore {
    registry: Arc<dyn Registry>,
    ca_state: Arc<Mutex<CaState>>,
    tunneled: Arc<AtomicUsize>,
}

impl ProxyCore {
    async fn accept_loop(
        self,
        listener: tokio::net::TcpListener,
        mut shutdown_rx: tokio::sync::oneshot::Receiver<()>,
    ) -> anyhow::Result<()> {
        loop {
            tokio::select! {
                accept_result = listener.accept() => {
                    let (stream, addr) = accept_result?;
                    debug!("accepted {}", addr);
                    let core = self.clone_core();
                    tokio::spawn(async move {
                        if let Err(e) = core.handle_connection(stream).await {
                            warn!("connection error: {:#}", e);
                        }
                    });
                }
                _ = &mut shutdown_rx => return Ok(()),
            }
        }
    }

    fn clone_core(&self) -> ProxyCore {
        ProxyCore {
            registry: self.registry.clone(),
            ca_state: self.ca_state.clone(),
            tunneled: self.tunneled.clone(),
        }
    }

    async fn handle_connection(&self, stream: TcpStream) -> anyhow::Result<()> {
        let mut reader = BufReader::new(stream);
        let mut first_line = Vec::new();
        reader.read_until(b'\n', &mut first_line).await?;
        let line = String::from_utf8_lossy(&first_line);

        if line.starts_with("CONNECT ") {
            let host_port = parse_connect_host(&line)?;
            let stream = reader.into_inner();
            self.handle_connect(stream, &host_port).await
        } else {
            handle_http(reader, first_line).await
        }
    }

    async fn handle_connect(&self, client: TcpStream, host_port: &str) -> anyhow::Result<()> {
        let (host, port) = parse_host_port(host_port);
        debug!("CONNECT {}:{}", host, port);

        let is_registry_host = self.registry.known_hosts().iter().any(|h| host == *h);
        if is_registry_host {
            self.handle_mitm(client, host, port).await
        } else {
            self.tunneled.fetch_add(1, Ordering::Relaxed);
            self.handle_tunnel(client, &host, port).await
        }
    }

    async fn handle_tunnel(&self, mut client: TcpStream, host: &str, port: u16) -> anyhow::Result<()> {
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
        &self,
        mut client: TcpStream,
        host: String,
        port: u16,
    ) -> anyhow::Result<()> {
        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;

        let acceptor = self.ca_state.lock().unwrap().tls_acceptor_for_host(&host)?;
        let tls_stream = acceptor.accept(client).await?;
        let io = TokioIo::new(tls_stream);

        let upstream = UpstreamForwarder { host: host.clone(), port };
        let svc = RegistryMiddleware {
            inner: upstream,
            registry: self.registry.clone(),
            mitm_host: host,
        };

        hyper::server::conn::http1::Builder::new()
            .serve_connection(io, svc)
            .await?;

        Ok(())
    }
}

#[derive(Clone)]
struct UpstreamForwarder {
    host: String,
    port: u16,
}

impl hyper::service::Service<hyper::Request<Incoming>> for UpstreamForwarder {
    type Response = hyper::Response<http_body_util::combinators::BoxBody<Bytes, String>>;
    type Error = anyhow::Error;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn call(&self, req: hyper::Request<Incoming>) -> Self::Future {
        let host = self.host.clone();
        let port = self.port;
        Box::pin(async move { forward_https(&host, port, req).await })
    }
}

#[derive(Clone)]
struct RegistryMiddleware {
    inner: UpstreamForwarder,
    registry: Arc<dyn Registry>,
    mitm_host: String,
}

impl hyper::service::Service<hyper::Request<Incoming>> for RegistryMiddleware {
    type Response = hyper::Response<http_body_util::combinators::BoxBody<Bytes, String>>;
    type Error = anyhow::Error;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn call(&self, req: hyper::Request<Incoming>) -> Self::Future {
        let inner = self.inner.clone();
        let registry = self.registry.clone();
        let host = self.mitm_host.clone();

        Box::pin(async move {
            let url = Url::parse(&format!("https://{}{}", host, req.uri())).ok();

            let mut req = req;
            if let Some(url) = &url {
                registry.prepare_request(url, req.headers_mut());
            }

            let resp = inner.call(req).await?;
            let (mut parts, body) = resp.into_parts();
            let bytes = collect_body(body).await?;

            let action = match &url {
                Some(url) => registry.handle_response(url, parts.status.as_u16(), &parts.headers, &bytes),
                None => ResponseAction::Passthrough,
            };

            match action {
                ResponseAction::Passthrough => {
                    Ok(hyper::Response::from_parts(parts, full_body(bytes)))
                }
                ResponseAction::Rewrite { body: new_body } => {
                    parts.headers.insert(
                        "content-length",
                        new_body.len().to_string().parse().unwrap(),
                    );
                    parts.headers.remove("content-encoding");
                    Ok(hyper::Response::from_parts(parts, full_body(new_body)))
                }
                ResponseAction::Block => {
                    let resp = hyper::Response::builder()
                        .status(403)
                        .body(full_body(b"Forbidden".to_vec()))
                        .unwrap();
                    Ok(resp)
                }
            }
        })
    }
}

async fn collect_body(
    body: http_body_util::combinators::BoxBody<Bytes, String>,
) -> anyhow::Result<Vec<u8>> {
    let collected = body
        .collect()
        .await
        .map_err(|e| anyhow::anyhow!("body collect: {e}"))?;
    Ok(collected.to_bytes().to_vec())
}

fn full_body(data: Vec<u8>) -> http_body_util::combinators::BoxBody<Bytes, String> {
    http_body_util::Full::new(Bytes::from(data))
        .map_err(|_| String::new())
        .boxed()
}

async fn forward_https(
    host: &str,
    port: u16,
    req: hyper::Request<Incoming>,
) -> anyhow::Result<hyper::Response<http_body_util::combinators::BoxBody<Bytes, String>>> {
    let mut builder = hyper::Request::builder()
        .method(req.method().clone())
        .uri(req.uri())
        .version(req.version())
        .header("host", host);

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
    for cert in rustls_native_certs::load_native_certs().expect("load native certs") {
        store.add(cert).ok();
    }
    Arc::new(store)
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

async fn handle_http(mut reader: BufReader<TcpStream>, first_line: Vec<u8>) -> anyhow::Result<()> {
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
