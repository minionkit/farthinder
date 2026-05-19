mod cert;
mod config;
mod install;
mod interceptor;
mod printer;
mod proxy;
mod registry;
mod rule;
mod sandbox;

use std::{env, process};

use clap::Parser;

#[derive(Parser)]
#[command(name = "fart", about = "Supply chain speed bump")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Debug, clap::Subcommand)]
enum Commands {
    Install,
    Uninstall,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let exe_name = current_exe_name()?;
    tracing::info!("farthinder starting, exe={}", exe_name);

    if exe_name == "fart" {
        let cli = Cli::parse();
        match cli.command {
            Some(Commands::Install) => install::install(),
            Some(Commands::Uninstall) => install::uninstall(),
            None => {
                Cli::parse_from(["fart", "--help"]);
                Ok(())
            }
        }
    } else {
        let interceptor = interceptor::Interceptor::new()?;
        let status = interceptor.run().await?;
        process::exit(status.code().unwrap_or(1));
    }
}

fn current_exe_name() -> anyhow::Result<String> {
    let exe = env::current_exe()?;
    let name = exe
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| anyhow::anyhow!("invalid exe path"))?;
    Ok(name.to_string())
}
