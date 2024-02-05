mod commands;
mod ethernet_frame;
mod ipv4;

use commands::ping::{recv_icmp_response, send_icmp_echo_request};

fn main() {
    // println!("Hello, world!");
    let mut sequence = 44;

    for _ in 0..10 {
        sequence += 1;
        send_and_recv(sequence);
    }
    fn send_and_recv(sequence: u16) {
        let sequence = sequence;
        let handle1 = std::thread::spawn(move || {
            send_icmp_echo_request(sequence);
        });

        let handle2 = std::thread::spawn(|| {
            recv_icmp_response();
        });

        handle1.join().unwrap();
        handle2.join().unwrap();
    }
}
