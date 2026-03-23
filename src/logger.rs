use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

pub fn init() -> anyhow::Result<()> {
    let env_filter =
        tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into());

    let fmt_layer = tracing_subscriber::fmt::layer().with_target(false);

    tracing_subscriber::registry()
        .with(fmt_layer)
        .try_init()
        .map_err(|e| anyhow::anyhow!("failed to initialize tracing: {}", e))
}
