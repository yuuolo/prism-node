use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use prism_node::{api, config, server::Node};
use tokio_util::sync::CancellationToken;

/// prism-node — AnyTLS server with a sing-box compatible config.
#[derive(Parser)]
#[command(version, about)]
struct Cli {
    /// Config file (sing-box format; only anytls inbounds are used)
    #[arg(short = 'c', long = "config", global = true, default_value = "/etc/prism-node/config.json")]
    config: PathBuf,
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the node (default)
    Run,
    /// Check the config and exit
    Check,
    /// Print per-user traffic counters of the running node (JSON)
    Stats {
        /// API address; default: api.listen from the config
        #[arg(long)]
        api: Option<String>,
    },
    /// Make the running node re-read its config (same as SIGHUP)
    Reload {
        #[arg(long)]
        api: Option<String>,
    },
    /// Print the version
    Version,
}

fn api_addr(cli: &Cli, flag: &Option<String>) -> Result<std::net::SocketAddr> {
    match flag {
        Some(a) => a.parse().with_context(|| format!("bad API address {a}")),
        None => config::api_addr(&cli.config)?.context("the API is disabled in the config (api.listen is empty)"),
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match &cli.cmd {
        None | Some(Cmd::Run) => run(&cli),
        Some(Cmd::Check) => {
            let cfg = config::load(&cli.config)?;
            for w in &cfg.warnings {
                println!("warning: {w}");
            }
            let users: usize = cfg.inbounds.iter().map(|i| i.users.len()).sum();
            println!("configuration ok: {} inbounds, {users} users", cfg.inbounds.len());
            Ok(())
        }
        Some(Cmd::Stats { api }) => {
            println!("{}", api::call(api_addr(&cli, api)?, "GET", "/stats")?);
            Ok(())
        }
        Some(Cmd::Reload { api }) => {
            println!("{}", api::call(api_addr(&cli, api)?, "POST", "/reload")?);
            Ok(())
        }
        Some(Cmd::Version) => {
            println!("prism-node {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
    }
}

fn run(cli: &Cli) -> Result<()> {
    let cfg = config::load(&cli.config)?;
    let level = match cfg.log_level.as_str() {
        "trace" | "debug" => "debug",
        "warn" | "warning" => "warn",
        "error" | "fatal" | "panic" => "error",
        "silent" => "off",
        _ => "info",
    };
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| level.into()))
        .with_ansi(false)
        .with_target(false)
        .init();
    tracing::info!("prism-node {} config={}", env!("CARGO_PKG_VERSION"), cli.config.display());
    for w in &cfg.warnings {
        tracing::warn!("{w}");
    }

    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    rt.block_on(async {
        let shutdown = CancellationToken::new();
        let node = Node::new(&cfg, Some(cli.config.clone()));
        drop(cfg);
        node.start(shutdown.clone()).await?;
        if let Some(addr) = node.api {
            let bound = api::serve(node.clone(), addr, shutdown.clone()).await.with_context(|| format!("api on {addr}"))?;
            tracing::info!("api listening on {bound}");
        }
        #[cfg(unix)]
        {
            let node = node.clone();
            let mut hup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;
            tokio::spawn(async move {
                while hup.recv().await.is_some() {
                    let n = node.clone();
                    match tokio::task::spawn_blocking(move || n.reload()).await {
                        Ok(Err(e)) => tracing::error!("reload failed, keeping the old config: {e:#}"),
                        Err(e) => tracing::error!("reload: {e}"),
                        Ok(Ok(_)) => {}
                    }
                }
            });
        }
        wait_for_exit().await;
        tracing::info!("shutting down");
        shutdown.cancel();
        Ok(())
    })
}

async fn wait_for_exit() {
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).unwrap();
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    let _ = tokio::signal::ctrl_c().await;
}
