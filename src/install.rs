use std::env;
use std::fs;
use std::path::PathBuf;

use anyhow::{Context, bail};
use askama::Template;
use tracing::info;

use crate::registry::ToolName;
use strum::IntoEnumIterator;

const MARKER_START: &str = "# >>> farthinder >>>";
const MARKER_END: &str = "# <<< farthinder <<<";

pub fn install() -> anyhow::Result<()> {
    let home = home_dir()?;
    let shim_dir = home.join("bin");
    let data_dir = home.join("data");

    fs::create_dir_all(&shim_dir).context("create shim directory")?;
    fs::create_dir_all(&data_dir).context("create data directory")?;

    let exe = env::current_exe().context("locate fart binary")?;
    let exe = exe
        .canonicalize()
        .context("resolve fart binary path")?;

    let found = scan_path_for_tools();

    if found.is_empty() {
        bail!("no supported package managers found on your PATH");
    }

    for name in &found {
        let shim = shim_dir.join(name);
        if shim.exists() {
            let existing = fs::read_link(&shim).ok();
            if existing.as_ref() == Some(&exe) {
                info!("shim {} already points to fart, skipping", name);
                continue;
            }
        }
        let _ = fs::remove_file(&shim);
        std::os::unix::fs::symlink(&exe, &shim)
            .with_context(|| format!("create shim symlink for {}", name))?;
        info!("created shim: {}", name);
    }

    let placeholder = data_dir.join("PLACEHOLDER.md");
    if !placeholder.exists() {
        fs::write(&placeholder, PLACEHOLDER_CONTENT)
            .context("write PLACEHOLDER.md")?;
    }

    inject_path()?;

    eprintln!();
    eprintln!("Created shims for {} tools:", found.len());
    for name in &found {
        eprintln!("  {}", name);
    }
    eprintln!();
    eprintln!("Shim directory: {}", shim_dir.display());
    eprintln!("Run `exec $SHELL` or open a new terminal to activate.");

    Ok(())
}

pub fn uninstall() -> anyhow::Result<()> {
    let home = home_dir()?;

    if home.exists() {
        fs::remove_dir_all(&home)
            .context("remove farthinder directory")?;
        info!("removed {}", home.display());
    }

    strip_path_injections()?;

    eprintln!("Removed farthinder.");
    eprintln!("Run `exec $SHELL` or open a new terminal to deactivate.");

    Ok(())
}

fn home_dir() -> anyhow::Result<PathBuf> {
    let home = env::var("HOME").context("HOME not set")?;
    Ok(PathBuf::from(home).join(".farthinder"))
}

fn scan_path_for_tools() -> Vec<String> {
    let path_var = env::var("PATH").unwrap_or_default();
    ToolName::iter()
        .filter(|tool| {
            env::split_paths(&path_var)
                .any(|dir| dir.join(tool.to_string()).exists())
        })
        .map(|tool| tool.to_string())
        .collect()
}

struct RcTarget {
    path: PathBuf,
    block: String,
}

fn inject_path() -> anyhow::Result<()> {
    for target in rc_targets() {
        if !target.path.exists() {
            continue;
        }

        let content = fs::read_to_string(&target.path)
            .with_context(|| format!("read {}", target.path.display()))?;

        let cleaned = strip_block(&content);
        let updated = format!("{cleaned}\n{block}\n", block = target.block);

        fs::write(&target.path, updated)
            .with_context(|| format!("write {}", target.path.display()))?;

        info!("updated {}", target.path.display());
    }

    Ok(())
}

fn strip_path_injections() -> anyhow::Result<()> {
    for target in rc_targets() {
        if !target.path.exists() {
            continue;
        }

        let content = fs::read_to_string(&target.path)
            .with_context(|| format!("read {}", target.path.display()))?;

        let cleaned = strip_block(&content);
        if cleaned != content {
            fs::write(&target.path, cleaned)
                .with_context(|| format!("write {}", target.path.display()))?;
            info!("cleaned {}", target.path.display());
        }
    }

    Ok(())
}

#[derive(Template)]
#[template(path = "shell/export.txt")]
struct ExportBlock;

#[derive(Template)]
#[template(path = "shell/path-array.txt")]
struct PathArrayBlock;

#[derive(Template)]
#[template(path = "shell/fish.txt")]
struct FishBlock;

fn rc_targets() -> Vec<RcTarget> {
    let home = env::var("HOME").unwrap_or_default();
    let home_pb = PathBuf::from(home);

    let export = block(ExportBlock);
    let path_array = block(PathArrayBlock);
    let fish = block(FishBlock);

    vec![
        RcTarget { path: home_pb.join(".zshenv"), block: export.clone() },
        RcTarget { path: home_pb.join(".zshrc"), block: path_array },
        RcTarget { path: home_pb.join(".bash_profile"), block: export.clone() },
        RcTarget { path: home_pb.join(".bashrc"), block: export },
        RcTarget { path: home_pb.join(".config/fish/config.fish"), block: fish },
    ]
}

fn block(tpl: impl Template) -> String {
    format!("{MARKER_START}\n{}\n{MARKER_END}", tpl.render().expect("shell template"))
}

fn strip_block(content: &str) -> String {
    let mut result = String::new();
    let mut skipping = false;

    for line in content.lines() {
        if line.trim() == MARKER_START {
            skipping = true;
            continue;
        }
        if line.trim() == MARKER_END {
            skipping = false;
            continue;
        }
        if !skipping {
            if !result.is_empty() {
                result.push('\n');
            }
            result.push_str(line);
        }
    }

    result
}

const PLACEHOLDER_CONTENT: &str = "# farthinder data directory\n\nThis directory will contain vulnerability databases and other runtime data.\n";
