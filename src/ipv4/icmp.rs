//! Module for ICMP (Internet Control Message Protocol) Packet Handling.
//!
//! This module defines the structure and functionalities for creating and parsing ICMP packets,
//! primarily used for network diagnostics such as ping.

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

/// Represents an ICMP packet.
pub(crate) struct ICMPPacket {
    /// Type of the ICMP packet.
    pub(crate) packet_type: u8,
    /// Code for the ICMP packet.
    pub(crate) code: u8,
    /// Checksum for error-checking.
    pub(crate) checksum: u16,
    /// Identifier, often used for matching requests with replies.
    pub(crate) identifier: u16,
    /// Sequence number, used to differentiate each packet uniquely.
    pub(crate) sequence: u16,
    /// Data payload of the ICMP packet.
    pub(crate) data: Vec<u8>,
}


impl ICMPPacket {
    /// Calculates the total length of the ICMP packet.
    pub(crate) fn len(&self) -> u16 {
        28 as u16 + self.data.len() as u16
    }

    /// Converts the ICMP packet into bytes for transmission.
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.packet_type);
        bytes.push(self.code);
        bytes.extend_from_slice(&self.checksum.to_be_bytes());
        bytes.extend_from_slice(&self.identifier.to_be_bytes());
        bytes.extend_from_slice(&self.sequence.to_be_bytes());
        bytes.extend_from_slice(&self.data);
        bytes
    }

    /// Converts a byte array into an ICMP packet.
    pub(crate) fn from_bytes(bytes: &[u8]) -> ICMPPacket {
        let packet_type = bytes[0];
        let code = bytes[1];
        let checksum = u16::from_be_bytes([bytes[2], bytes[3]]);
        let identifier = u16::from_be_bytes([bytes[4], bytes[5]]);
        let sequence = u16::from_be_bytes([bytes[6], bytes[7]]);
        let data = bytes[8..].to_vec();

        ICMPPacket {
            packet_type,
            code,
            checksum,
            identifier,
            sequence,
            data,
        }
    }

    // pub(crate) fn new() -> ICMPPacket {
    //     ICMPPacket {
    //         packet_type: 0,
    //         code: 0,
    //         checksum: [0, 0],
    //         identifier: [0, 0],
    //         sequence: [0, 0],
    //         // timestamp: [0, 0, 0, 0, 0, 0, 0, 0],
    //         data: vec![],
    //     }
    // }
    
    /// Creates a new ICMP Echo Request packet.
    /// 
    /// # Arguments
    ///* `sequence` - Sequence number of the packet.
    /// 
    pub(crate) fn new_echo_request(sequence: u16) -> ICMPPacket {
        let now = SystemTime::now();
        let data = time_to_bytes(now);

        let identifier: u16 = std::process::id() as u16;

        let mut packet = ICMPPacket {
            packet_type: 0x08,
            code: 0x00,
            checksum: 0,
            identifier,
            sequence,
            data,
        };
        let bytee = packet.to_bytes();

        packet.checksum = calculate_checksum(&bytee);
        return packet;
    }
}

/// Implements the Display trait for ICMPPacket.
impl fmt::Display for ICMPPacket {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ICMP: -----ICMP Header-----\n")?;
        write!(f, "ICMP:\n")?;
        write!(f, "ICMP: type= {}\n", self.packet_type)?;
        write!(f, "ICMP: Code= {}\n", self.code)?;
        write!(f, "ICMP: checksum= 0x{:x}\n", self.checksum)?;
        write!(f, "ICMP: identifier= 0x{:x}\n", self.identifier)?;
        write!(f, "ICMP: sequence= 0x{}\n", self.sequence)?;
        write!(f, "ICMP: -----ICMP Header-----\n")
    }
}

// ---------------HELPER FUNCTIONS----------------

/// Converts a SystemTime object into a byte array.
fn time_to_bytes(time: SystemTime) -> Vec<u8> {
    match time.duration_since(UNIX_EPOCH) {
        Ok(duration) => {
            let seconds = duration.as_secs();
            let nanos = duration.subsec_nanos();

            let mut bytes = Vec::new();
            bytes.extend_from_slice(&seconds.to_be_bytes()); // Big-endian representation
            bytes.extend_from_slice(&nanos.to_be_bytes()); // Big-endian representation

            bytes
        }
        Err(_) => {
            eprintln!("SystemTime before UNIX EPOCH!");
            Vec::new()
        }
    }
}

/// Calculates the checksum for the ICMP packet.
fn calculate_checksum(data: &Vec<u8>) -> u16 {
    let mut sum = 0u32; // Using u32 to avoid overflow during addition

    // Processing each 16-bit block
    let mut iter: std::slice::Chunks<'_, u8> = data.chunks(2);
    while let Some(chunk) = iter.next() {
        let word = if chunk.len() == 2 {
            ((chunk[0] as u16) << 8) + chunk[1] as u16 // Combinining two bytes into one word
        } else {
            (chunk[0] as u16) << 8 // If odd number of bytes, padding the last byte with zero
        };
        sum += word as u32;
    }

    // Add carry if any
    while (sum >> 16) > 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // One's complement of the sum
    !(sum as u16)
}
