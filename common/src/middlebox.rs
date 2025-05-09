use capsule::packets::{Mbuf, Packet};

pub struct Transformed {
    pub forward_packets: Vec<Mbuf>,
    pub return_packets: Vec<Mbuf>,
}

impl Transformed {
    pub fn new() -> Transformed {
        Transformed { forward_packets: Vec::new(), return_packets: Vec::new() }
    }

    pub fn unchanged(packet: impl Packet) -> Transformed {
        Transformed {
            forward_packets: vec![packet.reset()],
            return_packets: Vec::new(),
        }
    }
}

pub trait Middlebox {
    fn process_outgoing(&mut self, packet: Mbuf) -> Transformed;
    fn process_incoming(&mut self, packet: Mbuf) -> Transformed;
}
