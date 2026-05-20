use std::{net::SocketAddr, path::PathBuf};

use anyhow::Context;
use clap::Parser;
use fulcr::{app, store::Store};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[derive(Debug, Parser)]
#[command(about = "developer registry that protects developer environments")]
struct Args {
    #[arg(long, env = "fulcr_BIND", default_value = "127.0.0.1:8080")]
    bind: SocketAddr,

    #[arg(long, env = "fulcr_DATA_DIR", default_value = ".fulcr")]
    data_dir: PathBuf,

    #[arg(long, env = "fulcr_WORK_DIR", default_value = ".")]
    work_dir: PathBuf,
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
    let work_dir = std::fs::canonicalize(&args.work_dir)
        .unwrap_or_else(|_| args.work_dir.clone());
    let store = Store::open(args.data_dir)
        .await
        .context("opening fulcr data store")?;
        
    let store_clone = store.clone();
    tokio::spawn(async move {
        cache_sweep_loop(store_clone).await;
    });

    let app = app::router(store, work_dir);
    let listener = tokio::net::TcpListener::bind(args.bind)
        .await
        .with_context(|| format!("binding {}", args.bind))?;

    tracing::info!(%args.bind, "fulcr listening");
    axum::serve(listener, app).await.context("serving fulcr")?;
    Ok(())
}

async fn cache_sweep_loop(store: fulcr::store::Store) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
    loop {
        interval.tick().await;
        let _ = store.sweep_cache().await;
    }
}
