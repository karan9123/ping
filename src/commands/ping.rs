use crate::ethernet_frame::EthernetFrame;

extern crate libc;
use crate::ipv4::icmp::ICMPPacket;
use crate::ipv4::internet_packet::IPV4;
use libc::{ifreq, ioctl};
use std::os::unix::io::{AsRawFd, RawFd};
use std::{io::Write, mem};

/// This function will print the ping data.
pub(crate) fn print_ping(frame: &[u8]){
    let mut frame = EthernetFrame::from_bytes(frame);
    println!("{:?}", frame.packet.source_add);
    let ether_len = frame.to_bytes().len();
    print!("{}: ", ether_len);
}

/// Sends an ICMP echo request to the specified IP address.
pub(crate) fn send_icmp_echo_request(sequence: u16, source_ip_add: [u8; 4]) {
    let icmp_req = ICMPPacket::new_echo_request(sequence);
        
    let ipv4_packet = IPV4::new_icmp_from_ip(icmp_req, 64, source_ip_add);

    let mut ether_frame = EthernetFrame::new_ether(ipv4_packet);

    let pack = ether_frame.to_bytes();
    println!("{:?}", pack.len());

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

    let mut cap = pcap::Capture::from_device(device)
        .unwrap()
        .immediate_mode(true)
        .open()
        .unwrap();
    
    // Filter to read the ICMP echo response
    cap.filter("icmp[icmptype] == icmp-echoreply", false).unwrap();

    let data = cap.next_packet().unwrap().data;
    // let data = cap.filter(, optimize)

    print_ping(data);
}

/// Binds the BPF device to the specified interface.    
pub(crate) fn bind_bpf_to_interface(fd: RawFd, interface_name: &str) {

    unsafe {
        let mut ifr = ifreq {
            ifr_name: [0; libc::IFNAMSIZ],
            ifr_ifru: mem::zeroed(),
        };

        // Copy the interface name into the ifreq structure
        let bytes = interface_name.as_bytes();
        for (i, &byte) in bytes.iter().enumerate() {
            ifr.ifr_name[i] = byte as i8;
        }

        // Perform the ioctl operation to bind the BPF device to the interface
        if ioctl(fd, libc::BIOCSETIF, &ifr) == -1 {
            panic!("Failed to bind BPF device to interface");
        }
    }
}
