use std::fmt::Debug;

use capsule::packets::{Packet, ip::IpPacket, tcp::Tcp};

#[derive(Debug)]
struct Segment {
    start: usize,
    len: usize,
}

pub struct TcpBuffer {
    buf: Vec<u8>,
    max_capacity: usize,
    initial_seqno: u32,
    valid_data: usize,
    received_segments: Vec<Segment>,
}

impl TcpBuffer {
    pub fn new(initial_seqno: u32, capacity: usize) -> TcpBuffer {
        TcpBuffer {
            buf: Vec::new(),
            max_capacity: capacity,
            initial_seqno,
            valid_data: 0,
            received_segments: Vec::new(),
        }
    }

    fn process_valid_data(&mut self) {
        let mut keep_iterating = true;
        while keep_iterating {
            keep_iterating = false;
            for segment in &self.received_segments {
                if segment.start == self.valid_data {
                    self.valid_data += segment.len;
                    keep_iterating = true;
                    break;
                }
            }
        }
        self.received_segments
            .retain(|segment| segment.start > self.valid_data);
    }

    pub fn add_packet_data<E>(&mut self, packet: &Tcp<E>)
    where
        E: IpPacket,
    {
        let data_byte_offset = packet.data_offset() as usize * 4;
        let data_len = packet.len() - data_byte_offset;
        if data_len > 0 {
            if let Ok(data) = packet
                .mbuf()
                .read_data_slice(packet.offset() + data_byte_offset, data_len)
            {
                let data = unsafe { data.as_ref() };
                self.add_segment(packet.seq_no(), data);
            }
        }
    }

    pub fn add_segment(&mut self, seqno: u32, mut data: &[u8]) {
        let offset;
        if seqno < self.initial_seqno {
            offset = (u32::MAX - self.initial_seqno + seqno) as usize;
        } else {
            offset = (seqno - self.initial_seqno) as usize;
        }

        if offset >= self.max_capacity {
            return;
        }

        let mut end = offset + data.len();
        if end > self.max_capacity {
            data = &data[0..(self.max_capacity - offset)];
            end = self.max_capacity;
        }

        self.received_segments
            .retain(|segment| end <= segment.start || segment.start + segment.len <= offset);

        if end > self.buf.len() {
            self.buf.resize(end, 0);
        }
        self.buf[offset..end].copy_from_slice(data);
        self.received_segments.push(Segment {
            start: offset,
            len: data.len(),
        });
        self.process_valid_data();
    }

    pub fn len(&self) -> usize {
        self.valid_data
    }

    pub fn get_data(&self) -> &[u8] {
        &self.buf[0..self.valid_data]
    }

    pub fn drain(&mut self, length: usize) {
        self.initial_seqno += length as u32;
        self.buf.drain(..length);
        if self.valid_data > length {
            self.valid_data -= length;
        } else {
            self.valid_data = 0;
        }

        self.received_segments = self
            .received_segments
            .iter()
            .filter_map(|ele| {
                if ele.start < length {
                    None
                } else {
                    Some(Segment {
                        start: ele.start - length,
                        len: ele.len,
                    })
                }
            })
            .collect();
        self.process_valid_data();
    }
}

impl Debug for TcpBuffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TcpBuffer")
            .field("initial_seqno", &self.initial_seqno)
            .field("valid_data", &self.valid_data)
            .field("received_segments", &self.received_segments)
            .field("buffer_size", &self.buf.len())
            .finish()
    }
}
