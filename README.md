# ChatOverICMP

This program was created for the summer school at CTU (Czech technical university in Prague). The goal is to setup connection between two computers via antennas, then test connection by pinging each other and finally send messages between each other by this program!

## Requirements

- Python
- icmplib
- prompt_toolkit -> for better user experience with the program

```bash
pip3 install icmplib prompt_toolkit
```

If you get "externally-managed-enviroment" error, try to install it with `--break-system-packages` flag.
```bash
pip3 install icmplib prompt_toolkit --break-system-packages
```

## Usage

To use the `main.py` program, you need to provide the following arguments:

```
main.py [OPTIONS] <target_ip>
```

- `<target_ip>`: The IP address of the computer you want to communicate with.

Additionally, you can use the following options:

- `-m, --my-ip TEXT`: Your own IP address -> this is optional, if you don't provide it, the program will display messages from your address as if they were sent from other device to you.

Example usage:

```
main.py -m 192.168.0.1 192.168.0.2
```

This will start the program and sends user prompted messages to the target IP address.

Remember to replace `<target_ip>` with the actual IP address you want to communicate with.