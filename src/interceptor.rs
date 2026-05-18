use std::{
    env,
    os::unix::process::CommandExt,
    path::{Path, PathBuf},
    process::{Command, ExitStatus},
    sync::Arc,
};

use anyhow::Context;
use tracing::debug;

use crate::config;
use crate::printer::Printer;
use crate::proxy::ProxyServer;
use crate::registry::{Ecosystem, Registry};
use crate::rule::Rules;
use crate::sandbox::{self, SandboxPolicy, WrappedCommand};

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
        let Some(ecosystem) = &self.ecosystem else {
            let mut cmd = Command::new(&self.target);
            cmd.arg0(&self.arg0).args(env::args().skip(1));
            return cmd.status().context("execute command");
        };

        let cfg = config::load().unwrap_or_default();
        debug!("config: min_age_hours={}, sandbox_required={}", cfg.min_age_hours, cfg.sandbox_required);

        let rules = Rules::new(cfg.min_age_hours);
        let registry: Arc<dyn Registry> = Arc::from(ecosystem.registry(rules));
        let proxy = ProxyServer::spawn(registry.clone()).await?;
        let printer = Printer::new();

        printer.banner(*ecosystem);

        let ca_cert_path = write_ca_cert_temp(&proxy.ca_cert_pem)?;
        let proxy_port = proxy.port();

        let mut env_vars = match ecosystem {
            Ecosystem::Javascript => vec![
                ("npm_config_proxy".to_string(), proxy.url.clone()),
                ("npm_config_https_proxy".to_string(), proxy.url.clone()),
                ("HTTP_PROXY".to_string(), proxy.url.clone()),
                ("HTTPS_PROXY".to_string(), proxy.url.clone()),
                (
                    "NODE_EXTRA_CA_CERTS".to_string(),
                    ca_cert_path.to_string_lossy().to_string(),
                ),
            ],
            Ecosystem::Python => vec![
                ("HTTP_PROXY".to_string(), proxy.url.clone()),
                ("HTTPS_PROXY".to_string(), proxy.url.clone()),
                ("http_proxy".to_string(), proxy.url.clone()),
                ("https_proxy".to_string(), proxy.url.clone()),
                (
                    "REQUESTS_CA_BUNDLE".to_string(),
                    ca_cert_path.to_string_lossy().to_string(),
                ),
                (
                    "SSL_CERT_FILE".to_string(),
                    ca_cert_path.to_string_lossy().to_string(),
                ),
                (
                    "PIP_CERT".to_string(),
                    ca_cert_path.to_string_lossy().to_string(),
                ),
            ],
        };

        let enforcer = sandbox::get_enforcer();
        if cfg.sandbox_required && enforcer.is_none() {
            anyhow::bail!(
                "sandbox is required but no kernel enforcer is available on this platform"
            );
        }

        let status = if let Some(enforcer) = &enforcer {
            let policy = SandboxPolicy {
                proxy_port,
                deny_read_paths: sandbox::deny_read_paths(),
            };

            let wrapped = WrappedCommand {
                program: self.target.to_string_lossy().to_string(),
                args: env::args().skip(1).collect(),
                env: env_vars.clone(),
            };

            let sandboxed = enforcer.wrap_command(&policy, &wrapped)?;
            env_vars = sandboxed.env;

            let mut cmd = Command::new(&sandboxed.program);
            cmd.arg0(&self.arg0).args(&sandboxed.args);
            for (k, v) in &env_vars {
                cmd.env(k, v);
            }
            debug!("executing sandboxed {:?}", cmd.get_program());
            cmd.status().context("execute sandboxed command")
        } else {
            let mut cmd = Command::new(&self.target);
            cmd.arg0(&self.arg0).args(env::args().skip(1));
            for (k, v) in &env_vars {
                cmd.env(k, v);
            }
            debug!("executing unsandboxed");
            cmd.status().context("execute command")
        };

        let mut stats = registry.stats();
        stats.connections_tunneled = proxy.tunneled();
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
