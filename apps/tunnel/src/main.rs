use common::middlebox::Middlebox;

use std::sync::{
    Arc, Mutex,
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

    let middlebox = tls_validator::create_middlebox();
    let mutex = Arc::new(Mutex::new(middlebox));
    let mutex_clone = Arc::clone(&mutex);

    let inside_box = runtime.ports().get("inside")?.outbox()?;
    let inside_box_clone = inside_box.clone();
    let outside_box = runtime.ports().get("outside")?.outbox()?;
    let outside_box_clone = outside_box.clone();

    runtime.set_port_pipeline("inside", move |packet| {
        let result = mutex.lock().unwrap().process_outgoing(packet);
        for packet in result.forward_packets {
            let _ = outside_box.push(packet);
        }
        for packet in result.return_packets {
            let _ = inside_box.push(packet);
        }
        Ok(Postmark::Emit)
    })?;

    runtime.set_port_pipeline("outside", move |packet| {
        let result = mutex_clone.lock().unwrap().process_incoming(packet);
        for packet in result.forward_packets {
            let _ = inside_box_clone.push(packet);
        }
        for packet in result.return_packets {
            let _ = outside_box_clone.push(packet);
        }
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
