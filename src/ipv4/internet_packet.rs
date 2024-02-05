use crate::ipv4::icmp::ICMPPacket;

/// Represents an IPv4 packet.
pub(crate) struct IPV4 {
    /// Version and header length of the packet.
    pub(crate) version_header_len: u8,
    /// Differentiated Services Code Point (DSCP) and Explicit Congestion Notification (ECN).
    pub(crate) dscp_ecn: u8,
    /// Total length of the packet.
    pub(crate) total_length: u16,
    /// Identification of the packet.
    pub(crate) identification: u16,
    /// Flags and fragment offset of the packet.
    pub(crate) flags_fragment_offset: u16,
    /// Time to live of the packet.
    pub(crate) ttl: u8,
    /// Protocol of the packet.
    pub(crate) protocol: u8,
    /// Header checksum of the packet.
    pub(crate) header_checksum: u16,
    /// Source address of the packet.
    pub(crate) source_add: [u8; 4],
    /// Destination address of the packet.
    pub(crate) destination_add: [u8; 4],
    /// Options of the packet.
    pub(crate) options: Option<Vec<u8>>,
    /// Data payload of the packet.
    pub(crate) datagram: ICMPPacket,
}

impl IPV4 {

    /// Creates a new IPv4 packet from a byte array.
    pub(crate) fn from_bytes(bytes: &[u8]) -> IPV4 {
        let version_header_len = bytes[0];
        let dscp_ecn = bytes[1];
        let total_length = u16::from_be_bytes([bytes[2], bytes[3]]);
        let identification = u16::from_be_bytes([bytes[4], bytes[5]]);
        let flags_fragment_offset = u16::from_be_bytes([bytes[6], bytes[7]]);
        let ttl = bytes[8];
        let protocol = bytes[9];
        let header_checksum = u16::from_be_bytes([bytes[10], bytes[11]]);
        let source_add = [bytes[12], bytes[13], bytes[14], bytes[15]];
        let destination_add = [bytes[16], bytes[17], bytes[18], bytes[19]];
        let options = None;
        let datagram = ICMPPacket::from_bytes(&bytes[20..]);
        IPV4 {
            version_header_len,
            dscp_ecn,
            total_length,
            identification,
            flags_fragment_offset,
            ttl,
            protocol,
            header_checksum,
            source_add,
            destination_add,
            options,
            datagram,
        }
    }

    /// Creates a new IPv4 packet.
    /// 
    /// # Arguments
    /// * `datagram` - Data payload of the packet.
    /// * `protocol` - Protocol of the packet.
    /// * `ttl` - Time to live of the packet.
    /// * `options` - Options of the packet.
    /// 
    /// # Returns
    /// A new IPv4 packet.
    pub(crate) fn new(
        datagram: ICMPPacket,
        protocol: u8,
        ttl: u8,
        options: Option<Vec<u8>>,
    ) -> IPV4 {
        let mut version_header_len = 0x45; // First 4 bits for version, next 4 bits for header length
        if options.is_some() {
            let len: usize = options.as_ref().unwrap().len();

            let k = ceiling_division(len, 4);
            if k <= 4 {
                version_header_len = version_header_len + k as u8;
            }
        }
        let total_length = datagram.len();

        let mut ipv4 = IPV4 {
            version_header_len,
            dscp_ecn: 0,
            total_length,
            identification: 0,
            flags_fragment_offset: 0,
            ttl,
            protocol,
            header_checksum: 0,
            source_add: [172, 16, 67, 126],     //[192, 168, 0, 101], // Source IP Address of my computer
            destination_add: [142, 251, 35, 174], //Destination IP Address of Google.com
            options,
            datagram,
        };
        let bytee = ipv4.to_bytes();
        let checksum = calculate_ipv4_checksum(bytee);
        ipv4.header_checksum = checksum;
        return ipv4;
    }

    /// C0nverts the IPv4 packet into bytes for transmission.
    pub(crate) fn to_bytes(&mut self) -> Vec<u8> {
        let mut result = Vec::new();
        result.push(self.version_header_len);
        result.push(self.dscp_ecn);
        let total_length = u16_to_bytes_big_endian(self.total_length);
        result.push(total_length[0]);
        result.push(total_length[1]);
        let identification = u16_to_bytes_big_endian(self.identification);
        result.push(identification[0]);
        result.push(identification[1]);
        let flags_fragment_offset = u16_to_bytes_big_endian(self.flags_fragment_offset);
        result.push(flags_fragment_offset[0]);
        result.push(flags_fragment_offset[1]);
        result.push(self.ttl);
        result.push(self.protocol);
        let header_checksum = u16_to_bytes_big_endian(self.header_checksum);
        result.push(header_checksum[0]);
        result.push(header_checksum[1]);
        result.append(&mut self.source_add.to_vec());
        result.append(&mut self.destination_add.to_vec());
        let options = self.options.clone();
        if options.is_some() {
            let mut p = options.as_ref().unwrap().clone();
            result.append(&mut p);
        }
        result.append(&mut self.datagram.to_bytes());
        return result;
    }

    ///Creates a new ICMP packet from an IPv4 packet.
    pub(crate) fn new_icmp_from_ip(datagram: ICMPPacket, ttl: u8) -> IPV4 {
        IPV4::new(datagram, 1, ttl, None)
    }

    /*    pub(crate) fn new_with_ttl(datagram: ICMPPacket, ttl: u8,
                               total_length: [u8; 2], identification: [u8; 2],
                               source_add: [u8; 4], destination_add: [u8; 4]) -> IPacket {
        IPacket {
            version: IPVersion::V4,
            ihl: 0,
            tos: 0,
            precedence: 0,
            delay: 0,
            throughput: 0,
            reliability: 0,
            total_length,
            identification,
            reserved_flag: 0,
            do_not_fragment_flag: 0,
            last_fragment_flag: 0,
            fragment_offset: 0,
            ttl,
            protocol: IPProtocol::ICMP,
            header_checksum: [0, 0],
            source_add,
            destination_add,
            options: None,
            datagram,
        }
    }*/
}

///Implement Display for IPV4
impl std::fmt::Display for IPV4 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "\nIPV4 Packet: -----Packet Header-----")?;
        write!(f, "IPV4: Version/Header Length: {:x}\n", self.version_header_len)?;
        write!(f, "IPV4: DSCP/ECN: {}\n", self.dscp_ecn)?;
        write!(f, "IPV4: Total Length: {:x}\n", self.total_length)?;
        write!(f, "IPV4: Identification: {}\n", self.identification)?;
        write!(f, "IPV4: Flags/Fragment Offset: {}\n", self.flags_fragment_offset)?;
        write!(f, "IPV4: TTL: {}\n", self.ttl)?;
        write!(f, "IPV4: Protocol: {}\n", self.protocol)?;
        write!(f, "IPV4: Header Checksum: {}\n", self.header_checksum)?;
        write!(
            f,
            "IPV4: Source Address: {}\n",
            format_ipv4_address(&self.source_add)
        )?;
        write!(
            f,
            "IPV4: Destination Address: {}\n",
            format_ipv4_address(&self.destination_add)
        )?;

        if let Some(ref options) = self.options {
            write!(f, "IPV4: Options: {:?}\n", options)?;
        } else {
            write!(f, "IPV4: Options: None\n")?;
        }
        write!(f, "IPV4 Packet: -----Packet Header-----\n\n")?;
        write!(f, "Datagram: \n{}", self.datagram)
    }
}

// --------------HELPER FUNCTIONS----------------

/// Calculates the checksum of an IPv4 packet.
fn ceiling_division(dividend: usize, divisor: usize) -> u8 {
    if divisor == 0 {
        panic!("Attempted to divide by zero");
    }

    ((dividend + divisor - 1) / divisor) as u8
}

/// Converts a u16 value into a [u8; 2] array in big-endian order.
fn u16_to_bytes_big_endian(value: u16) -> [u8; 2] {
    [
        (value >> 8) as u8, // Shift right to get the MSB
        value as u8,        // Cast to u8 to get the LSB
    ]
}

/// Calculates the checksum of an IPv4 packet.
fn calculate_ipv4_checksum(header: Vec<u8>) -> u16 {
    assert!(header.len() % 2 == 0, "Header length must be even");

    let mut sum = 0u32;

    // Iterate over each 16-bit word
    for word in header.chunks(2) {
        let part = u16::from_be_bytes([word[0], word[1]]);
        sum += part as u32;
    }

    // Add carry if present
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // Return the one's complement of the sum as a [u8; 2] array
    !(sum as u16)
}

/// Formats an IPv4 address into a human-readable string.
fn format_ipv4_address(addr: &[u8; 4]) -> String {
    format!("{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3])
}
