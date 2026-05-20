use std::path::Path;

use landlock::{Access, Compatible, RulesetAttr, RulesetCreatedAttr};

use super::{SandboxEnforcer, SandboxPolicy, WrappedCommand};

pub struct LandlockEnforcer;

impl LandlockEnforcer {
    pub fn is_available() -> bool {
        probe_abi().is_some()
    }
}

impl SandboxEnforcer for LandlockEnforcer {
    fn wrap_command(
        &self,
        policy: &SandboxPolicy,
        cmd: &WrappedCommand,
    ) -> anyhow::Result<WrappedCommand> {
        use std::os::unix::process::CommandExt;
        use std::process::Command;

        let abi = landlock::ABI::V4;

        let mut ruleset = landlock::Ruleset::default()
            .set_compatibility(landlock::CompatLevel::BestEffort)
            .handle_access(landlock::AccessFs::from_all(abi))?;

        if abi >= landlock::ABI::V4 {
            ruleset = ruleset.handle_access(landlock::AccessNet::ConnectTcp)?;
        }

        let mut created = ruleset.create()?;

        for path in BASELINE_READ_PATHS {
            if Path::new(path).exists() {
                created = created.add_rule(landlock::PathBeneath::new(
                    std::fs::File::open(path)?,
                    landlock::AccessFs::from_read(abi),
                ))?;
            }
        }

        // Landlock is purely additive — there is no deny-overrides mechanism like macOS SBPL.
        // We enumerate allowed write paths explicitly; sensitive paths (.ssh, .aws, etc.)
        // are simply not included, so they remain inaccessible.
        // This is fragile: if we miss a path a package manager needs, it will EPERM at runtime.
        // TODO: Consider a more robust strategy — enumerate subpaths of $HOME to allow,
        // or use a helper that lists known cache/config dirs per ecosystem.
        let mut write_paths: Vec<&Path> = BASELINE_WRITE_PATHS.iter().map(Path::new).collect();
        write_paths.push(&policy.cwd);
        write_paths.push(&policy.home);

        for path in &write_paths {
            if path.exists() {
                created = created.add_rule(landlock::PathBeneath::new(
                    std::fs::File::open(path)?,
                    landlock::AccessFs::from_all(abi),
                ))?;
            }
        }

        if abi >= landlock::ABI::V4 {
            created = created.add_rule(landlock::NetPort::new(
                policy.proxy_port,
                landlock::AccessNet::ConnectTcp,
            ))?;
        }

        let mut cmd_build = Command::new(&cmd.program);
        cmd_build.args(&cmd.args);
        for (k, v) in &cmd.env {
            cmd_build.env(k, v);
        }

        let created = std::sync::Mutex::new(Some(created));

        unsafe {
            cmd_build.pre_exec(move || {
                let rc = libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
                if rc != 0 {
                    return Err(std::io::Error::last_os_error());
                }

                let ruleset = created
                    .lock()
                    .unwrap()
                    .take()
                    .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::Other))?;

                ruleset.restrict_self().map(|_| ()).map_err(|_| {
                    std::io::Error::from(std::io::ErrorKind::PermissionDenied)
                })
            });
        }

        Ok(WrappedCommand {
            program: cmd.program.clone(),
            args: cmd.args.clone(),
            env: cmd.env.clone(),
        })
    }
}

const BASELINE_READ_PATHS: &[&str] = &[
    "/etc",
    "/lib",
    "/lib32",
    "/lib64",
    "/usr",
    "/proc",
    "/sys",
    "/dev",
];

const BASELINE_WRITE_PATHS: &[&str] = &[
    "/tmp",
    "/var/tmp",
    "/dev/null",
    "/dev/zero",
    "/dev/shm",
];

fn probe_abi() -> Option<u32> {
    let raw = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<libc::c_void>(),
            0_usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if raw >= 4 {
        Some(raw as u32)
    } else {
        None
    }
}

const LANDLOCK_CREATE_RULESET_VERSION: u64 = 1;
