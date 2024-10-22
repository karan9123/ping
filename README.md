# Rust Networking Tool

This is a Rust-based networking tool that includes a low-level implementation of networking protocols like Ethernet and IPv4, and features an ICMP "ping" utility. This tool provides a way to understand and manipulate raw network frames using Rust.

## Features
- **Ethernet Frame Parsing**: Construct, parse, and display Ethernet frames with source and destination MAC addresses, EtherType, and encapsulated IPv4 packets.
- **IPv4 Packet Processing**: Handle IPv4 packets, including checksum calculations and header parsing.
- **ICMP Ping Utility**: Send ICMP Echo Requests to test network connectivity and gather response times.

## Project Structure
The directory structure of the project is as follows:

```
├── src
│   ├── main.rs                # Entry point of the application
│   ├── ethernet_frame.rs      # Defines Ethernet frame structure and functionality
│   ├── icmp.rs                # Implements ICMP packet structure and handling
│   ├── internet_packet.rs     # Handles IPv4 packet parsing and creation
│   ├── ping.rs                # Implements ICMP Echo Request (ping) functionality
│   ├── mod.rs                 # Organizes and imports modules
```

### Module Overview
- **`main.rs`**: The entry point of the program, orchestrating the execution flow.
- **`ethernet_frame.rs`**: Contains the definition for Ethernet frames, including functions to create, parse, and display Ethernet frames.
- **`icmp.rs`**: Handles ICMP packet generation, parsing, and checksum calculations.
- **`internet_packet.rs`**: Implements the IPv4 packet structure, including header fields and utility functions like checksum calculation.
- **`ping.rs`**: Implements the logic to send ICMP Echo Requests to a target IP address and handle the responses to simulate a "ping" operation.
- **`mod.rs`**: Imports all modules to provide a unified interface for the main program.

## Getting Started

### Prerequisites
- **Rust**: Ensure that you have Rust installed. You can install it from [rust-lang.org](https://www.rust-lang.org/tools/install).

### Building the Project
To build the project, run:
```sh
cargo build --release
```

### Running the Project
You can run the project using:
```sh
cargo run
```

This will execute the main logic, which by default sends ICMP Echo Requests to a target IP address.

### Example Usage
To use the ping functionality, you can modify the target IP address in the `ping.rs` file or extend the main function to accept user input for the target address.

## Future Improvements and Modifications
1. **Add IPv6 Support**: Extend the current implementation to handle IPv6 packets, allowing the tool to function in modern networking environments that use IPv6.
2. **User Input for Target IP**: Modify the `main.rs` to accept command-line arguments for specifying the target IP address, allowing dynamic ping targets.
3. **Add ARP Packet Handling**: Implement ARP (Address Resolution Protocol) functionality to translate IP addresses to MAC addresses within local networks.
4. **Multithreaded Ping Requests**: Allow sending multiple ICMP Echo Requests concurrently using Rust's concurrency features to speed up the ping process.
5. **Detailed Packet Inspection**: Enhance packet inspection capabilities to include more detailed logging and packet analysis for diagnostic purposes.
6. **Unit Tests for Modules**: Add comprehensive unit tests for each module to ensure the robustness of Ethernet, IPv4, and ICMP functionalities.
7. **Interactive CLI Interface**: Implement an interactive command-line interface to choose between different packet types (Ethernet, IPv4, ICMP) for creation, parsing, and transmission.
8. **Error Handling Improvements**: Improve error handling and add meaningful error messages to make debugging easier, especially for invalid packet construction or network errors.

## Contributing
Contributions are welcome! Please feel free to open issues or submit pull requests to help improve this project.

### Steps to Contribute
1. Fork this repository.
2. Create a new branch (`git checkout -b feature-branch`).
3. Make your changes and commit them (`git commit -m 'Add new feature'`).
4. Push to the branch (`git push origin feature-branch`).
5. Open a Pull Request.

## License
This project is licensed under the MIT License. See the `LICENSE` file for more details.

## Acknowledgements
- This project uses Rust's low-level capabilities to provide a better understanding of how networking protocols are implemented.
- Inspired by the desire to learn about packet-level operations and Rust's system-level programming capabilities.

## Contact
For any questions or suggestions, please feel free to contact the project maintainer via email or open an issue in the repository.



## Not to used for malicious purposes.
