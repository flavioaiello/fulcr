use std::{net::SocketAddr, path::PathBuf};

use anyhow::Context;
use clap::Parser;
use fulcr::{app, store::Store};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Debug, Parser)]
#[command(about = "developer registry that protects developer environments")]
struct Args {
    #[arg(long, env = "FULCR_BIND", default_value = "127.0.0.1:8080")]
    bind: SocketAddr,

    #[arg(long, env = "FULCR_DATA_DIR", default_value = ".fulcr")]
    data_dir: PathBuf,

    #[arg(long, env = "FULCR_WORK_DIR", default_value = ".")]
    work_dir: PathBuf,

    #[arg(long, env = "FULCR_ALLOW_INSECURE_REMOTE", default_value_t = false)]
    allow_insecure_remote: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("fulcr=info,tower_http=info")),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let args = Args::parse();
    if !args.bind.ip().is_loopback() && !args.allow_insecure_remote {
        anyhow::bail!(
            "refusing plaintext non-loopback bind {}; use a loopback TLS proxy or set FULCR_ALLOW_INSECURE_REMOTE=true explicitly",
            args.bind
        );
    }
    let work_dir = std::fs::canonicalize(&args.work_dir).unwrap_or_else(|_| args.work_dir.clone());
    let store = Store::open(args.data_dir)
        .await
        .context("opening fulcr data store")?;

    let store_clone = store.clone();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let cache_task = tokio::spawn(async move {
        cache_sweep_loop(store_clone, shutdown_rx).await;
    });

    let app = app::router(store, work_dir);
    let listener = tokio::net::TcpListener::bind(args.bind)
        .await
        .with_context(|| format!("binding {}", args.bind))?;

    tracing::info!(%args.bind, "fulcr listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            shutdown_signal().await;
            let _ = shutdown_tx.send(true);
        })
        .await
        .context("serving fulcr")?;
    cache_task.await.context("joining cache sweep task")?;
    Ok(())
}

async fn cache_sweep_loop(
    store: fulcr::store::Store,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
    loop {
        tokio::select! {
            _ = interval.tick() => {
                if let Err(error) = store.sweep_cache().await {
                    tracing::error!(?error, "cache sweep failed");
                }
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
        }
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            tracing::error!(?error, "failed to install Ctrl-C handler");
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(error) => tracing::error!(?error, "failed to install SIGTERM handler"),
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
    tracing::info!("shutdown signal received");
}
