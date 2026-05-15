use std::{
    env,
    os::unix::process::CommandExt,
    path::{Path, PathBuf},
    process::{Command, ExitStatus},
};

use anyhow::Context;
use tracing::debug;

use crate::printer::Printer;
use crate::proxy::ProxyServer;
use crate::registry::Ecosystem;

pub struct Interceptor {
    target: PathBuf,
    arg0: String,
    ecosystem: Option<Ecosystem>,
}

impl Interceptor {
    pub fn new() -> anyhow::Result<Self> {
        let arg0 = env::args()
            .next()
            .ok_or_else(|| anyhow::anyhow!("no argv[0]"))?;
        let tool_name = Path::new(&arg0)
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| anyhow::anyhow!("invalid exe name"))?;
        let target = find_target_executable(tool_name)?;
        let ecosystem = match tool_name {
            "bun" | "bunx" | "npm" | "npx" | "pnpm" | "yarn" => Some(Ecosystem::Javascript),
            "pip" | "pip3" | "uv" | "uvx" | "pipx" | "poetry" => Some(Ecosystem::Python),
            _ => None,
        };
        Ok(Interceptor {
            target,
            arg0,
            ecosystem,
        })
    }

    pub async fn run(&self) -> anyhow::Result<ExitStatus> {
        let mut cmd = Command::new(&self.target);
        cmd.arg0(&self.arg0).args(env::args().skip(1));

        let Some(ecosystem) = &self.ecosystem else {
            return cmd.status().context("execute command");
        };

        let proxy = ProxyServer::spawn(Some(*ecosystem)).await?;
        let printer = Printer::new();

        printer.banner(*ecosystem);

        let ca_cert_path = write_ca_cert_temp(&proxy.ca_cert_pem)?;

        match ecosystem {
            Ecosystem::Javascript => {
                cmd.env("npm_config_proxy", &proxy.url)
                    .env("npm_config_https_proxy", &proxy.url)
                    .env("HTTP_PROXY", &proxy.url)
                    .env("HTTPS_PROXY", &proxy.url)
                    .env(
                        "NODE_EXTRA_CA_CERTS",
                        ca_cert_path.to_string_lossy().as_ref(),
                    );
            }
            Ecosystem::Python => {
                cmd.env("HTTP_PROXY", &proxy.url)
                    .env("HTTPS_PROXY", &proxy.url)
                    .env("http_proxy", &proxy.url)
                    .env("https_proxy", &proxy.url)
                    .env(
                        "REQUESTS_CA_BUNDLE",
                        ca_cert_path.to_string_lossy().as_ref(),
                    )
                    .env("SSL_CERT_FILE", ca_cert_path.to_string_lossy().as_ref())
                    .env("PIP_CERT", ca_cert_path.to_string_lossy().as_ref());
            }
        }

        debug!("executing {:?}", cmd.get_envs());
        let status = cmd.status().context("execute command");
        let stats = proxy.stats();
        proxy.shutdown();
        let _ = std::fs::remove_file(&ca_cert_path);

        if stats.active() {
            printer.summary(&stats);
        }

        status
    }
}

fn write_ca_cert_temp(pem: &str) -> anyhow::Result<PathBuf> {
    let dir = std::env::temp_dir().join("farthinder");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("ca.pem");
    std::fs::write(&path, pem)?;
    Ok(path)
}

fn find_target_executable(tool_name: &str) -> anyhow::Result<PathBuf> {
    let path_var = env::var("PATH")?;
    let current_exe = env::current_exe()?;
    let shim_dir = current_exe
        .parent()
        .ok_or_else(|| anyhow::anyhow!("shim has no parent dir"))?;

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

    anyhow::bail!("no target executable for {}", tool_name)
}
