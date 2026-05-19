use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use askama::Template;

use super::{SandboxEnforcer, SandboxPolicy, WrappedCommand};

const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";

pub struct MacosEnforcer;

impl MacosEnforcer {
    pub fn is_available() -> bool {
        Path::new(SANDBOX_EXEC).exists()
    }
}

impl SandboxEnforcer for MacosEnforcer {
    fn wrap_command(
        &self,
        policy: &SandboxPolicy,
        cmd: &WrappedCommand,
    ) -> anyhow::Result<WrappedCommand> {
        let sbpl = generate_sbpl(policy);
        let sbpl_path = write_sbpl_tempfile(&sbpl)?;

        let mut args = vec![
            "-f".to_string(),
            sbpl_path.to_string_lossy().to_string(),
            cmd.program.clone(),
        ];
        args.extend(cmd.args.iter().cloned());

        let mut env = cmd.env.clone();
        env.push((
            "__FARTHINDER_SBPL_PATH".to_string(),
            sbpl_path.to_string_lossy().to_string(),
        ));

        Ok(WrappedCommand {
            program: SANDBOX_EXEC.to_string(),
            args,
            env,
        })
    }
}

fn write_sbpl_tempfile(content: &str) -> anyhow::Result<std::path::PathBuf> {
    let dir = std::env::temp_dir().join("farthinder");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("sbpl-{}.sbpl", std::process::id()));
    std::fs::write(&path, content)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400))?;
    Ok(path)
}

#[derive(Template)]
#[template(path = "sbpl.txt")]
struct SbplTemplate {
    proxy_port: u16,
    cwd: String,
    home: String,
    sensitive_paths: Vec<String>,
    has_sensitive_paths: bool,
}

fn generate_sbpl(policy: &SandboxPolicy) -> String {
    let paths: Vec<String> = policy
        .sensitive_paths
        .iter()
        .map(|p| p.display().to_string())
        .collect();
    let has = !paths.is_empty();
    SbplTemplate {
        proxy_port: policy.proxy_port,
        cwd: policy.cwd.display().to_string(),
        home: policy.home.display().to_string(),
        sensitive_paths: paths,
        has_sensitive_paths: has,
    }
    .render()
    .expect("SBPL template rendering")
}

#[cfg(test)]
use std::sync::atomic::{AtomicU32, Ordering};

#[cfg(test)]
static TEST_ID: AtomicU32 = AtomicU32::new(0);

#[cfg(test)]
fn next_test_id() -> u32 {
    TEST_ID.fetch_add(1, Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::path::PathBuf;
    use std::process::Command;
    use std::thread;

    fn can_run_sandbox_tests() -> bool {
        MacosEnforcer::is_available()
    }

    fn write_test_sbpl(policy: &SandboxPolicy) -> std::path::PathBuf {
        let sbpl = generate_sbpl(policy);
        let dir = std::env::temp_dir().join("farthinder-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(format!("test-{}-{}.sbpl", std::process::id(), next_test_id()));
        std::fs::write(&path, &sbpl).unwrap();
        path
    }

    fn run_under_sbpl(proxy_port: u16, url: &str) -> std::process::Output {
        let policy = SandboxPolicy {
            proxy_port,
            cwd: std::env::current_dir().unwrap(),
            home: directories::BaseDirs::new()
                .map(|bd| bd.home_dir().to_path_buf())
                .unwrap_or_default(),
            sensitive_paths: vec![],
        };
        let sbpl_path = write_test_sbpl(&policy);

        let output = Command::new(SANDBOX_EXEC)
            .arg("-f")
            .arg(&sbpl_path)
            .arg("/usr/bin/curl")
            .arg("--connect-timeout")
            .arg("2")
            .arg("--max-time")
            .arg("5")
            .arg("-s")
            .arg("-o")
            .arg("/dev/null")
            .arg("-w")
            .arg("%{http_code}")
            .arg(url)
            .output()
            .expect("spawn curl under sandbox-exec");

        let _ = std::fs::remove_file(&sbpl_path);
        output
    }

    fn start_responder(listener: TcpListener) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                stream.set_read_timeout(Some(std::time::Duration::from_secs(2))).ok();
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf);
                let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
                let _ = stream.flush();
            }
        })
    }

    #[test]
    fn sbpl_contains_deny_default() {
        let policy = SandboxPolicy {
            proxy_port: 8080,
            cwd: PathBuf::from("/Users/test/project"),
            home: PathBuf::from("/Users/test"),
            sensitive_paths: vec![PathBuf::from("/Users/test/.ssh")],
        };
        let sbpl = generate_sbpl(&policy);
        assert!(sbpl.contains("(deny default)"));
        assert!(sbpl.contains("(deny file-read*"));
        assert!(sbpl.contains("(subpath \"/Users/test/.ssh\")"));
        assert!(sbpl.contains("(remote tcp \"localhost:8080\")"));
    }

    #[test]
    fn sandbox_allows_proxy_port() {
        if !can_run_sandbox_tests() {
            eprintln!("skipping: sandbox-exec not available");
            return;
        }

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind proxy port");
        let proxy_port = listener.local_addr().unwrap().port();
        let handle = start_responder(listener);

        let output = run_under_sbpl(proxy_port, &format!("http://localhost:{proxy_port}"));

        handle.join().ok();

        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "sandbox should allow curl to proxy port localhost:{proxy_port}\n\
             stdout: {stdout}\nstderr: {}",
            String::from_utf8_lossy(&output.stderr),
        );
    }

    #[test]
    fn sandbox_blocks_non_proxy_localhost_port() {
        if !can_run_sandbox_tests() {
            eprintln!("skipping: sandbox-exec not available");
            return;
        }

        let proxy_listener = TcpListener::bind("127.0.0.1:0").expect("bind proxy port");
        let proxy_port = proxy_listener.local_addr().unwrap().port();
        drop(proxy_listener);

        let forbidden_listener = TcpListener::bind("127.0.0.1:0").expect("bind forbidden port");
        let forbidden_port = forbidden_listener.local_addr().unwrap().port();
        let _handle = start_responder(forbidden_listener);

        let output = run_under_sbpl(proxy_port, &format!("http://localhost:{forbidden_port}"));

        assert!(
            !output.status.success(),
            "sandbox should block curl to non-proxy localhost:{forbidden_port}\n\
             stdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }

    #[test]
    fn sandbox_blocks_external_network() {
        if !can_run_sandbox_tests() {
            eprintln!("skipping: sandbox-exec not available");
            return;
        }

        let proxy_listener = TcpListener::bind("127.0.0.1:0").expect("bind proxy port");
        let proxy_port = proxy_listener.local_addr().unwrap().port();
        drop(proxy_listener);

        let output = run_under_sbpl(proxy_port, "http://example.com");

        assert!(
            !output.status.success(),
            "sandbox should block curl to external host example.com\n\
             stdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
}
