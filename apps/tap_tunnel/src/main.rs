use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use anyhow::Result;
use capsule::{
    packets::Postmark,
    runtime::{self, Runtime},
};
use signal_hook::{consts, flag};
use tracing::{Level, info};

fn main() -> Result<()> {
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let config = runtime::load_config()?;
    let runtime = Runtime::from_config(config)?;

    let outbox_1 = runtime.ports().get("cap1")?.outbox()?;
    runtime.set_port_pipeline("cap0", move |packet| {
        let _ = outbox_1.push(packet);
        Ok(Postmark::Emit)
    })?;

    let outbox_0 = runtime.ports().get("cap0")?.outbox()?;
    runtime.set_port_pipeline("cap1", move |packet| {
        let _ = outbox_0.push(packet);
        Ok(Postmark::Emit)
    })?;

    let _guard = runtime.execute();

    let term = Arc::new(AtomicBool::new(false));
    flag::register(consts::SIGINT, term.clone())?;
    info!("ctrl-c to quit...");
    loop {
        if term.load(Ordering::Relaxed) {
            break;
        }
    }

    Ok(())
}
