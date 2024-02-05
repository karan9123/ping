use crate::ethernet_frame::EthernetFrame;

extern crate libc;
use crate::ipv4::icmp::ICMPPacket;
use crate::ipv4::internet_packet::IPV4;
use libc::{ifreq, ioctl};
use std::os::unix::io::{AsRawFd, RawFd};
use std::{io::Write, mem};

#[repr(C)]
struct bpf_program {
    bf_len: u16, // Length of the program in instructions
    bf_insns: *const bpf_insn, // Pointer to the array of BPF instructions
}
struct bpf_insn {
    code: u8,   /* Operation code */
    jt: u8,    /* Jump true */
    jf: u8,     /* Jump false */
    k: u8,      /* Generic field */
}


/// Sends an ICMP echo request to the specified IP address.
pub(crate) fn send_icmp_echo_request(sequence: u16) {
    let icmp_req = ICMPPacket::new_echo_request(sequence);

    let ipv4_packet = IPV4::new_icmp_from_ip(icmp_req, 64);

    let mut ether_frame = EthernetFrame::new_ether(ipv4_packet);

    println!("{}", ether_frame);

    let pack = ether_frame.to_bytes();

    let mut bpf_device = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/bpf243")
        .expect("Failed to open BPF device");
    let bpf_fd: RawFd = bpf_device.as_raw_fd();

    // Bind to an interface
    bind_bpf_to_interface(bpf_fd, "en0");

    bpf_device.write_all(&pack).expect("Failed to write packet");
}

/// Receives an ICMP echo response.
pub(crate) fn recv_icmp_response() {
    let device = pcap::Device::lookup()
        .expect("device lookup failed")
        .expect("no device available");
    println!("Using device {}", device.name);

    let mut cap = pcap::Capture::from_device(device)
        .unwrap()
        .immediate_mode(true)
        .open()
        .unwrap();

    // get a packet and print its bytes
    // println!("{:?}", cap.next_packet());

    let data = cap.next_packet().unwrap().data;

    let frame = EthernetFrame::from_bytes(data);
    println!("{}", frame);
}
// -------------------HELPER FUNCTIONS----------------
/// Binds the BPF device to the specified interface.    
pub(crate) fn bind_bpf_to_interface(fd: RawFd, interface_name: &str) {

    // let bpf_insns = [
    //     // 1. Load Ethernet header offset
    //     bpf_insn { code: 0x20, jt: 0, jf: 0, k: 14 },
    //     // 2. Load IP header offset
    //     bpf_insn { code: 0x28, jt: 0, jf: 0, k: 14 },
    //     // 3. Check IP protocol (ICMP = 1)
    //     bpf_insn { code: 0x15, jt: 0, jf: 5, k: 1 },
    //     // 4. Load ICMP header offset
    //     bpf_insn { code: 0x28, jt: 0, jf: 0, k: 20 },
    //     // 5. Check ICMP type (Echo Reply = 0)
    //     bpf_insn { code: 0x15, jt: 0, jf: 1, k: 0 },
    //     // 6. Accept the packet
    //     bpf_insn { code: 0x06, jt: 0, jf: 0, k: 0 },
    //     // 7. Reject the packet (if not a ping response)
    //     bpf_insn { code: 0x06, jt: 0, jf: 0, k: 0 },
    // ];

    unsafe {
        let mut ifr = ifreq {
            ifr_name: [0; libc::IFNAMSIZ],
            ifr_ifru: mem::zeroed(),
        };

        // let bpf_insns = [
    //     // 1. Load Ethernet header offset
    //     bpf_insn { code: 0x20, jt: 0, jf: 0, k: 14 },
    //     // 2. Load IP header offset
    //     bpf_insn { code: 0x28, jt: 0, jf: 0, k: 14 },
    //     // 3. Check IP protocol (ICMP = 1)
    //     bpf_insn { code: 0x15, jt: 0, jf: 5, k: 1 },
    //     // 4. Load ICMP header offset
    //     bpf_insn { code: 0x28, jt: 0, jf: 0, k: 20 },
    //     // 5. Check ICMP type (Echo Reply = 0)
    //     bpf_insn { code: 0x15, jt: 0, jf: 1, k: 0 },
    //     // 6. Accept the packet
    //     bpf_insn { code: 0x06, jt: 0, jf: 0, k: 0 },
    //     // 7. Reject the packet (if not a ping response)
    //     bpf_insn { code: 0x06, jt: 0, jf: 0, k: 0 },
    // ];


    // let bpf_program = bpf_program {
    //     bf_len: bpf_insns.len() as u16,
    //     bf_insns: bpf_insns.as_ptr(),
    // };

        // Copy the interface name into the ifreq structure
        let bytes = interface_name.as_bytes();
        for (i, &byte) in bytes.iter().enumerate() {
            ifr.ifr_name[i] = byte as i8;
        }
        // unsafe{
        // Perform the ioctl operation to bind the BPF device to the interface
        if ioctl(fd, libc::BIOCSETIF, &ifr) == -1 {
            panic!("Failed to bind BPF device to interface");
        }
    }
}
