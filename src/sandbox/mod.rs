#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "linux")]
mod linux;

use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct SandboxPolicy {
    pub proxy_port: u16,
    pub cwd: PathBuf,
    pub home: PathBuf,
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub sensitive_paths: Vec<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct WrappedCommand {
    pub program: String,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
}

pub trait SandboxEnforcer: Send + Sync {
    fn wrap_command(&self, policy: &SandboxPolicy, cmd: &WrappedCommand) -> anyhow::Result<WrappedCommand>;
}

pub fn get_enforcer() -> Option<Box<dyn SandboxEnforcer>> {
    #[cfg(target_os = "macos")]
    {
        if macos::MacosEnforcer::is_available() {
            return Some(Box::new(macos::MacosEnforcer));
        }
    }
    #[cfg(target_os = "linux")]
    {
        if linux::LandlockEnforcer::is_available() {
            return Some(Box::new(linux::LandlockEnforcer));
        }
    }
    None
}

pub fn sensitive_paths() -> Vec<PathBuf> {
    let home = directories::BaseDirs::new()
        .map(|bd| bd.home_dir().to_path_buf())
        .unwrap_or_else(|| PathBuf::from(std::env::var("HOME").unwrap_or_default()));
    let mut paths = vec![
        home.join(".ssh"),
        home.join(".aws"),
        home.join(".gnupg"),
        home.join(".config").join("gcloud"),
        home.join(".kube"),
    ];
    for name in &[".env", ".env.local", ".env.production", ".env.production.local"] {
        let p = home.join(name);
        if p.exists() {
            paths.push(p);
        }
    }
    paths
}
