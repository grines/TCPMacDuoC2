# TCPMacDuoC2

TCPMacDuoC2 is a command-and-control (C2) server specifically designed for Mac systems, featuring a dual-port TCP communication mechanism. This tool allows for efficient and secure management of remote systems through encrypted commands and responses.

## Features

- Dual-port TCP server for enhanced communication.
- Encrypted command transmission for security.
- Reconnection handling for maintaining persistent control.
- Command-line interface for easy interaction.
- OSX Keychain access
- OSX Clipboard
- Syscalls for common commands

## Installation

To install TCPMacDuoC2, follow these steps:

1. Clone the repository:
   ```
   git clone https://github.com/grines/TCPMacDuoC2.git
   ```
2. Navigate to the cloned directory:
   ```
   cd TCPMacDuoC2
   ```
3. Compile the code (ensure you have Go installed):
   ```
   go build cli_remote.go
   go build multi_serv.go
   go build payload.go
   ```

## Usage

To use TCPMacDuoC2, you need to start both the server and the client.

1. Start the server. This should be a publically avaiable server with 8009 and 8008 ports open:
   ```
   ./multi_serv
   ```
2. In a separate terminal, from your client machine start the client:
   ```
   ./cli_remote -ip <server_ip> -port <server_port>
   ```
3. Run the payload on a target machine
   ```
   ./payload
   ```

Replace `<server_ip>` and `<server_port>` with the appropriate values.

### Available Commands

- `list`: Lists all connected implants.
- `select <implant_id>`: Selects an implant to interact with.
- `current`: Shows the currently selected implant.
- `keychain`: Access an OSX keychain service name
- `clipboard`: Access the OSX clipboard data.
- `osascript`: Run osascript on the victims machine

## Disclaimer

This tool is developed for educational and ethical testing purposes only. The author is not responsible for any misuse or damage caused by this tool.

## Contributing

Contributions to TCPMacDuoC2 are welcome. Please feel free to submit pull requests, report bugs, and suggest new features.

## License

[MIT License](LICENSE)

---

For more information, please refer to the [documentation](#) or [issues](https://github.com/yourusername/TCPMacDuoC2/issues) section.

