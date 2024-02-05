use crate::ipv4::internet_packet::IPV4;

use std::fmt;

///Represents an Ethernet frame.
pub(crate) struct EthernetFrame {
    ///Destination MAC address.
    pub(crate) destination_address: [u8; 6],
    ///Source MAC address.
    pub(crate) source_address: [u8; 6],
    ///EtherType of the frame.
    pub(crate) ether_type: [u8; 2],
    ///Packet payload of the frame.(Support for IPv4 only)
    pub(crate) packet: IPV4,
}

impl EthernetFrame {

    ///Converts the Ethernet frame into bytes for transmission.
    pub(crate) fn to_bytes(&mut self) -> Vec<u8> {
        let mut result = Vec::new();
        result.append(&mut self.destination_address.to_vec());
        result.append(&mut self.source_address.to_vec());
        result.append(&mut self.ether_type.to_vec());
        result.append(&mut self.packet.to_bytes());
        return result;
    }

    ///Converts a byte array into an Ethernet frame.
    pub(crate) fn from_bytes(bytes: &[u8]) -> EthernetFrame {
        let mut destination_address = [0; 6];
        let mut source_address = [0; 6];
        let mut ether_type = [0; 2];
        // let mut packet = IPV4::new();
        destination_address.copy_from_slice(&bytes[0..6]);
        source_address.copy_from_slice(&bytes[6..12]);
        ether_type.copy_from_slice(&bytes[12..14]);
        let packet = IPV4::from_bytes(&bytes[14..]);
        EthernetFrame {
            destination_address,
            source_address,
            ether_type,
            packet,
        }
    }

    ///Creates a new Ethernet frame.
    /// 
    /// # Arguments
    /// * `packet` - Packet payload of the frame.
    ///     
    /// # Returns
    /// A new Ethernet frame.
    pub(crate) fn new_ether(packet: IPV4) -> EthernetFrame {
        EthernetFrame {
            destination_address: [0xff, 0xff, 0xff, 0xff, 0xff, 0xff],//[0x48, 0xa9, 0x8a, 0x3f, 0xb8, 0x5e],//[0xAC, 0x84, 0xC6, 0x67, 0x43, 0x8C],
            source_address: [0x3c, 0x06, 0x30, 0x36, 0x61, 0x6c],
            ether_type: [0x08, 0x00],
            packet,
        }
    }
}

///Implements the Display trait for EthernetFrame.
impl fmt::Display for EthernetFrame {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ETHER: -----Ether Header-----\n")?;
        write!(f, "ETHER:\n")?;
        write!(
            f,
            "ETHER: Destination= {:x}:{:x}:{:x}:{:x}:{:x}:{:x}\n",
            self.destination_address[0],
            self.destination_address[1],
            self.destination_address[2],
            self.destination_address[3],
            self.destination_address[4],
            self.destination_address[5]
        )?;
        write!(
            f,
            "ETHER: Source     = {:x}:{:x}:{:x}:{:x}:{:x}:{:x}\n",
            self.source_address[0],
            self.source_address[1],
            self.source_address[2],
            self.source_address[3],
            self.source_address[4],
            self.source_address[5]
        )?;
        write!(
            f,
            "ETHER: Ethertype  = 0x{:x}{:x}\n",
            self.ether_type[0], self.ether_type[1]
        )?;
        write!(f, "ETHER: -----Ether Header-----\n")?;
        write!(f, "\nPacket: \n{}", self.packet)
    }
}
