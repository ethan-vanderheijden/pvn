use anyhow::Result;
use capsule::packets::{
    Mbuf, Packet,
    ethernet::Ethernet,
    ip::{IpPacket, ProtocolNumbers},
    tcp::Tcp,
};
use rustls::internal::msgs::{
    codec::Codec, handshake::HandshakeMessagePayload, handshake::HandshakePayload,
};

use crate::tcp_buffer::TcpBuffer;

pub const TLS_HEADER_LENGTH: u16 = 5;
pub const TLS_MAX_RECORD_LENGTH: u16 = 16384;

const TLS_HANDSHAKE_RECORD: u8 = 0x16;

pub struct HandshakeMessage<'a> {
    pub is_tls12: bool,
    pub total_len: usize,
    pub payload: HandshakePayload<'a>,
}

fn read_handshake_frame(data: &[u8]) -> Result<(u8, u16), ()> {
    let record_type = data[0];
    let tls_major_version = data[1];
    let tls_minor_version = data[2];
    let length = ((data[3] as u16) << 8) | (data[4] as u16);
    // Some clients send ClientHello with TLS v1.0 frame for compatibility with old servers
    // In TLS v1.3, data is encapsulated with TLS v1.2 records
    // For these reasons, be very careful with how you use tls_minor_version
    if record_type != TLS_HANDSHAKE_RECORD || tls_major_version != 0x03 || length > 16384 {
        Err(())
    } else {
        Ok((tls_minor_version, length))
    }
}

pub fn read_handshake_msg(buffer: &TcpBuffer) -> Result<Option<HandshakeMessage>, ()> {
    if buffer.len() < TLS_HEADER_LENGTH as usize {
        // not enough data buffered yet
        return Ok(None);
    }

    let Ok((minor_version, record_length)) = read_handshake_frame(buffer.get_data()) else {
        // probably not a TLS flow
        return Err(());
    };

    if (buffer.get_data().len() - TLS_HEADER_LENGTH as usize) < (record_length as usize) {
        // not enough data buffered yet
        return Ok(None);
    }

    let start = TLS_HEADER_LENGTH as usize;
    let end = (TLS_HEADER_LENGTH + record_length) as usize;
    let Ok(handshake) = HandshakeMessagePayload::read_bytes(&buffer.get_data()[start..end]) else {
        // TLS handshake frame should be complete
        // so if handshake failed to decode, this probably isn't a real TLS flow
        return Err(());
    };
    Ok(Some(HandshakeMessage {
        is_tls12: minor_version == 3, // since 3.3 corresponds to TLSv1.2
        total_len: end,
        payload: handshake.payload,
    }))
}

pub fn generate_return_rst<E>(original: &Tcp<E>, seqno: u32) -> Result<Mbuf>
where
    E: IpPacket,
    E: Packet<Envelope = Ethernet>,
{
    let packet = Mbuf::new()?;

    let mut packet = packet.push::<Ethernet>()?;
    packet.set_dst(original.envelope().envelope().src());
    packet.set_src(original.envelope().envelope().dst());

    let mut packet = packet.push::<E>()?;
    packet.set_src(original.envelope().dst())?;
    packet.set_dst(original.envelope().src())?;
    packet.set_next_protocol(ProtocolNumbers::Tcp);

    let mut packet = packet.push::<Tcp<E>>()?;
    packet.set_dst_port(original.src_port());
    packet.set_src_port(original.dst_port());
    packet.set_seq_no(seqno);
    packet.set_rst();

    packet.reconcile_all();
    Ok(packet.reset())
}
