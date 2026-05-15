use std::{
    env::{self, Args, ArgsOs},
    os::unix::process::CommandExt,
    path::{Path, PathBuf},
    process::{self, Command, ExitStatus},
    str::FromStr,
};

use anyhow::Context;
use strum::{EnumProperty, EnumString};
use tokio::sync::oneshot;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let interceptor = Interceptor::new()?;
    let status = interceptor.run().await?;
    process::exit(status.code().unwrap_or(1))
}

#[derive(Debug, PartialEq)]
enum Ecosystem {
    Javascript,
    Python,
    Rust, //Rust = 2,
}

struct Interceptor {
    target: PathBuf,
    arg0: String,
    ecosystem: Option<Ecosystem>,
}

struct ProxyServer {
    shutdown_tx: oneshot::Sender<()>,
    url: String,
}

impl ProxyServer {
    async fn spawn() -> anyhow::Result<Self> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .context("Failed to bind to random port")?;

        let proxy_addr = listener.local_addr()?;
        let proxy_url = format!("http://{}", proxy_addr);
        eprintln!("My proxy {}", proxy_url);
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        tokio::spawn(ProxyServer::run(listener, shutdown_rx));

        Ok(ProxyServer {
            shutdown_tx,
            url: proxy_url,
        })
    }

    async fn run(
        listener: tokio::net::TcpListener,
        mut shutdown_rx: oneshot::Receiver<()>,
    ) -> anyhow::Result<()> {
        loop {
            // tokio::select! allows us to wait for new connections OR the shutdown signal
            tokio::select! {
                // Accept new connection
                accept_result = listener.accept() => {
                    match accept_result {
                        Ok((stream, _addr)) => {
                            eprintln!("Accepting {}", _addr);
                            // Handle the connection (spawn a task so we don't block the accept loop)
                            tokio::spawn(async move {
                                // TODO: Implement your actual proxy logic here
                                // e.g., parse HTTP request, scan for vulns, forward traffic.
                                // This is where you would use `hyper` or `tokio-native-tls`.
                                let _ = stream;
                            });
                        }
                        Err(e) => eprintln!("[Proxy] Accept error: {}", e),
                    }
                }

                // Check for shutdown signal
                _ = &mut shutdown_rx => {
                    return Ok(())
                }
            }
        }
    }
}

impl Interceptor {
    async fn run(&self) -> anyhow::Result<ExitStatus> {
        let mut cmd = Command::new(&self.target);
        cmd.arg0(&self.arg0).args(env::args().skip(1));

        let Some(ecosystem) = &self.ecosystem else {
            return cmd.status().context("Could not execute command");
        };

        let proxy = ProxyServer::spawn().await?;

        match ecosystem {
            Ecosystem::Javascript => {
                cmd.env("npm_config_proxy", &proxy.url)
                    .env("npm_config_https_proxy", &proxy.url)
                    .env("HTTP_PROXY", &proxy.url)
                    .env("HTTPS_PROXY", &proxy.url);
                // .env("NODE_EXTRA_CA_CERTS", CA_CERT_PATH);
            }
            Ecosystem::Python => {
                cmd.env("HTTP_PROXY", &proxy.url)
                    .env("HTTPS_PROXY", &proxy.url)
                    .env("http_proxy", &proxy.url)
                    .env("https_proxy", &proxy.url);
                // .env("REQUESTS_CA_BUNDLE", CA_CERT_PATH)
                // .env("SSL_CERT_FILE", CA_CERT_PATH)
                // .env("PIP_CERT", CA_CERT_PATH);
            }
            _ => unimplemented!(),
        }
        eprintln!("{:?}", cmd.get_envs());
        let status = cmd.status().context("Could not execute command");
        let _ = proxy.shutdown_tx.send(());
        status
    }
}

impl Interceptor {
    fn new() -> anyhow::Result<Self> {
        let arg0 = env::args()
            .next()
            .ok_or_else(|| anyhow::anyhow!("Failed to get argv[0]"))?;
        let tool_name = Path::new(&arg0)
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| anyhow::anyhow!("Invalid UTF-8 in executable name"))?;
        let target = find_target_executable(tool_name)?;
        let ecosystem = match tool_name {
            "bun" | "bunx" => Some(Ecosystem::Javascript),
            "pip" | "uv" | "uvx" | "pipx" => Some(Ecosystem::Python),
            _ => None,
        };
        Ok(Interceptor {
            target,
            arg0,
            ecosystem,
        })
    }
}

fn find_target_executable(tool_name: &str) -> anyhow::Result<PathBuf> {
    let path_var = env::var("PATH")?;
    let current_exe = env::current_exe()?;
    let shim_dir = current_exe
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Shim has no parent dir"))?;

    let mut found_shim = false;

    for path_dir in env::split_paths(&path_var) {
        let potential_bin = path_dir.join(tool_name);

        #[cfg(windows)]
        let potential_bin = if !potential_bin.exists() {
            path_dir.join(format!("{}.exe", tool_name))
        } else {
            potential_bin
        };

        if potential_bin.exists() {
            if !found_shim && potential_bin.parent() == Some(shim_dir) {
                found_shim = true;
                continue;
            }
            return Ok(potential_bin);
        }
    }

    anyhow::bail!("Could not find target executable for {}", tool_name)
}
