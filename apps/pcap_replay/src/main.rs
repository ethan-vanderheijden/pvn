use std::{
    ops::DerefMut,
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

use anyhow::{Result, anyhow};
use capsule::{
    net::MacAddr,
    packets::{Mbuf, Packet, Postmark, ethernet::Ethernet},
    runtime::{self, Outbox, Runtime},
};
use common::middlebox::Middlebox;
use tracing::Level;

fn process_packet(
    packet: Mbuf,
    middlebox: &mut impl Middlebox,
    outbox: &Outbox,
) -> Result<Postmark> {
    let eth = packet.peek::<Ethernet>()?;
    if eth.src() == MacAddr::new(0xf4, 0x26, 0x79, 0x69, 0xf8, 0xca) {
        let result = middlebox.process_outgoing(packet);
        for packet in result
            .forward_packets
            .into_iter()
            .chain(result.return_packets)
        {
            let _ = outbox.push(packet);
        }
    } else if eth.dst() == MacAddr::new(0xf4, 0x26, 0x79, 0x69, 0xf8, 0xca) {
        let result = middlebox.process_incoming(packet);
        for packet in result
            .forward_packets
            .into_iter()
            .chain(result.return_packets)
        {
            let _ = outbox.push(packet);
        }
    } else {
        return Err(anyhow!("Packet is not going to or from client!"));
    }
    Ok(Postmark::Emit)
}

fn main() -> Result<()> {
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(Level::DEBUG)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let config = runtime::load_config()?;
    let runtime = Runtime::from_config(config)?;

    let middlebox = tls_validator::create_middlebox();
    let mutex = Arc::new(Mutex::new(middlebox));

    let outbox = runtime.ports().get("cap0")?.outbox()?;
    runtime.set_port_pipeline("cap0", move |packet| {
        let mut middlebox = mutex.lock().unwrap();
        process_packet(packet, middlebox.deref_mut(), &outbox)
    })?;

    let _guard = runtime.execute();

    thread::sleep(Duration::from_secs(3));

    Ok(())
}
