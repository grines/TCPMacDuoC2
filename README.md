# TCPMacDuoC2

TCPMacDuoC2 is a command-and-control (C2) server specifically designed for Mac systems, featuring a dual-port TCP communication mechanism. This tool allows for efficient and secure management of remote systems through encrypted commands and responses. The goal of this project is to have a lightweight fast C2 for rapid payload developement and deployment. This code can be ran as is with little configuration.

## Features

- Dual-port TCP server for real time terminal access via client and server.
- Can handle mutiple implants.
- Multiuser capabilities
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
3. Run the payload on a target machine. Ensure to update the target address to point to the multi_serv
   ```
   ./payload
   ```

Replace `<server_ip>` and `<server_port>` with the appropriate values.

### Available Commands

- `list`: Lists all connected implants.
- `select <implant_id>`: Selects an implant to interact with.
- `current`: Shows the currently selected implant.
- `osascript`: Executes an AppleScript command.
- `osascript_url`: Executes an AppleScript command from a provided URL.
- `env`: Retrieves the environment variables of the system.
- `ping`: Responds with "pong" to check if the implant is alive.
- `whoami`: Returns the current user name.
- `ps`: Lists all running processes.
- `clipboard`: Retrieves the current content of the clipboard.
- `screenshot`: Takes a screenshot of the current screen.
- `cd`: Changes the current working directory.
- `download`: Downloads a specified file from the target system.
- `upload`: Uploads a file to the target system.
- `pwd`: Shows the current working directory.
- `keychain`: Retrieves passwords stored in the keychain for a specified service.
- `portscan`: Scans for open ports on the target system.
- `cp`: Copies a file from one location to another.
- `mv`: Moves a file from one location to another.
- `curl`: Fetches the content from a URL.
- `kill`: Terminates a process by its PID.
- `cat`: Displays the content of a file.
- `rm`: Removes a specified file.
- `ls`: Lists files in a specified directory or the current directory if none is specified.
- `default`: If the command is not recognized, it is executed in the shell.

## Disclaimer

This tool is developed for educational and ethical testing purposes only. The author is not responsible for any misuse or damage caused by this tool.

## Contributing

Contributions to TCPMacDuoC2 are welcome. Please feel free to submit pull requests, report bugs, and suggest new features.

## License

[MIT License](LICENSE)

---

For more information, please refer to the [documentation](#) or [issues](https://github.com/grines/TCPMacDuoC2/issues) section.

