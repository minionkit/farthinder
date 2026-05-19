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
use crate::registry::{Ecosystem, InterceptDecision, Registry, ToolName};
use crate::rule::Rules;
use crate::sandbox::{self, SandboxPolicy, WrappedCommand};

#[derive(Debug)]
pub struct Interceptor {
    target: PathBuf,
    arg0: String,
    tool: Option<ToolName>,
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
        let tool = tool_name.parse::<ToolName>().ok();
        let ecosystem = tool.and_then(|t| t.ecosystem());
        Ok(Interceptor {
            target,
            arg0,
            tool,
            ecosystem,
        })
    }

    pub async fn run(&self) -> anyhow::Result<ExitStatus> {
        let args: Vec<String> = env::args().skip(1).collect();

        let decision = match (self.tool, self.ecosystem) {
            (Some(tool), Some(eco)) => eco.decide(tool, args),
            _ => {
                let mut cmd = Command::new(&self.target);
                cmd.arg0(&self.arg0).args(&args);
                let e = cmd.exec();
                return Err(e.into());
            }
        };

        match decision {
            InterceptDecision::Passthrough(args) => {
                let mut cmd = Command::new(&self.target);
                cmd.arg0(&self.arg0).args(&args);
                let e = cmd.exec();
                Err(e.into())
            }
            InterceptDecision::Intercept(args) => {
                self.run_intercepted(args).await
            }
        }
    }

    async fn run_intercepted(&self, args: Vec<String>) -> anyhow::Result<ExitStatus> {
        let eco = self.ecosystem.unwrap();
        let cfg = config::load()?;
        debug!("config: min_age_hours={}, sandbox_required={}", cfg.min_age_hours, cfg.sandbox_required);

        let rules = Rules::new(cfg.min_age_hours);
        let registry: Arc<dyn Registry> = Arc::from(eco.registry(rules));
        let proxy = ProxyServer::spawn(registry.clone()).await?;
        let printer = Printer::new();

        printer.banner(eco);

        let ca_cert_path = write_ca_cert_temp(&proxy.ca_cert_pem)?;
        let proxy_port = proxy.port();

        let proxy_env = registry.proxy_env_vars(&proxy.url, &ca_cert_path);

        let enforcer = sandbox::get_enforcer();
        if cfg.sandbox_required && enforcer.is_none() {
            anyhow::bail!(
                "sandbox is required but no kernel enforcer is available on this platform"
            );
        }

        let status = if let Some(enforcer) = &enforcer {
            let home = directories::BaseDirs::new()
                .map(|bd| bd.home_dir().to_path_buf())
                .unwrap_or_else(|| PathBuf::from(env::var("HOME").unwrap_or_default()));

            let policy = SandboxPolicy {
                proxy_port,
                cwd: env::current_dir().context("get cwd")?,
                home,
                sensitive_paths: sandbox::sensitive_paths(),
            };

            let wrapped = WrappedCommand {
                program: self.target.to_string_lossy().to_string(),
                args,
                env: proxy_env,
            };

            let sandboxed = enforcer.wrap_command(&policy, &wrapped)?;
            let mut cmd = build_command(&sandboxed, &self.arg0);
            debug!("executing sandboxed {:?}", cmd.get_program());
            cmd.status().context("execute sandboxed command")
        } else {
            let wrapped = WrappedCommand {
                program: self.target.to_string_lossy().to_string(),
                args,
                env: proxy_env,
            };
            let mut cmd = build_command(&wrapped, &self.arg0);
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

fn build_command(wrapped: &WrappedCommand, arg0: &str) -> Command {
    let mut cmd = Command::new(&wrapped.program);
    cmd.arg0(arg0).args(&wrapped.args);
    for (k, v) in &wrapped.env {
        cmd.env(k, v);
    }
    cmd
}

fn write_ca_cert_temp(pem: &str) -> anyhow::Result<PathBuf> {
    let dir = std::env::temp_dir().join("farthinder");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("ca-{}.pem", std::process::id()));
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
