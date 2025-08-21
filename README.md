# Raw Socket Communication System

A peer-to-peer communication protocol implementation using raw IP sockets with reliable message delivery and file transfer capabilities.

## Quick Start

1. **Download and setup**:
```bash
git clone <repository-url>
cd raw-socket-communication
sudo python3 setup.py
```

2. **Start server**:
```bash
sudo python3 raw_socket_server.py
```

3. **Use client (in another terminal)**:
```bash
sudo python3 client_example.py interactive
```

## Requirements

- **Operating System**: Linux (recommended), macOS
- **Python**: 3.6 or higher
- **Privileges**: Root access (required for raw sockets)
- **Network**: Local network access, firewall configured for protocols 170-171

## Features

- Custom peer-to-peer protocol using IP protocols 170 (messages) and 171 (files)
- Reliable delivery with acknowledgments and automatic retransmission
- Chunked file transfer with automatic reassembly
- Real-time message communication
- Peer discovery functionality
- Built-in logging and error recovery

## File Structure

```
raw-socket-communication/
├── raw_socket_server.py    # Core communication engine
├── client.py       # Client library and examples
├── setup.py               # Automated setup script
├── README.md              # This file
└── shared_files/          # Created automatically
    └── received/          # Received files stored here
```

## Usage Examples

### Basic Server Mode
```bash
sudo python3 raw_socket_server.py
```
Interactive commands:
- `send 192.168.1.100 Hello World` - Send message
- `file 192.168.1.100 /path/to/file.txt` - Send file
- `status` - Show system status
- `messages` - Check received messages

### Client Library Mode
```bash
# Interactive mode
sudo python3 client_example.py interactive

# Example usage
sudo python3 client_example.py example

# Peer discovery
sudo python3 client_example.py discover
```

### Programmatic Usage
```python
from raw_socket_server import start_raw_socket_threads, send_message, get_received_messages

# Start the system
start_raw_socket_threads()

# Send a message
send_message("192.168.1.100", "Hello!", sender="myapp")

# Check for received messages
messages = get_received_messages()
for source_ip, message in messages:
    print(f"From {source_ip}: {message['content']}")
```

## API Reference

### Core Functions

**`start_raw_socket_threads()`**
- Starts all communication threads
- Must be called before using other functions

**`send_message(dest_ip, message, sender="anonymous", channel_id="general")`**
- Send text message to another peer
- Returns: `bool` (success/failure)

**`send_file(source_ip, recipients, file_path, channel_id, sender)`**
- Send file to list of recipients
- `recipients`: List of (ip, user_id) tuples
- Returns: `bool` (success/failure)

**`get_received_messages(timeout=0.1)`**
- Get list of received messages
- Returns: List of (source_ip, message_dict) tuples

**`get_system_status()`**
- Get system status information
- Returns: Dict with system metrics

**`stop_system()`**
- Gracefully shutdown the communication system

### Message Format
```python
{
    "content": "message text",
    "sender": "username",
    "channel_id": "channel_name",
    "timestamp": "2024-01-01T12:00:00Z",
    "is_file": 0  # 1 for file messages
}
```

## Network Configuration

### Firewall Setup (Linux)
```bash
sudo iptables -A INPUT -p 170 -j ACCEPT
sudo iptables -A INPUT -p 171 -j ACCEPT
sudo iptables -A OUTPUT -p 170 -j ACCEPT
sudo iptables -A OUTPUT -p 171 -j ACCEPT
```

### Testing Network Connectivity
```bash
# Check if protocols are working
sudo tcpdump -i any proto 170 or proto 171

# Test between two machines
# Machine A (192.168.1.100):
sudo python3 -c "
from raw_socket_server import *
start_raw_socket_threads()
time.sleep(2)
send_message('192.168.1.101', 'Hello from A!')
"

# Machine B (192.168.1.101):
sudo python3 -c "
from raw_socket_server import *
start_raw_socket_threads()
time.sleep(5)
messages = get_received_messages(timeout=2)
print('Received:', messages)
"
```

## Configuration

Key settings in `raw_socket_server.py`:

```python
MESSAGE_PROTOCOL = 170        # Protocol for messages
FILE_TRANSFER_PROTOCOL = 171  # Protocol for files
CHUNK_SIZE = 4096            # File chunk size (bytes)
MAX_RETRIES = 5              # Retransmission attempts
RETRY_TIMEOUT = 2.0          # Base timeout (seconds)
BACKOFF_FACTOR = 1.5         # Exponential backoff
```

## Troubleshooting

### Common Issues

**"Operation not permitted" error**
```bash
# Solution: Run with root privileges
sudo python3 raw_socket_server.py
```

**No messages received**
```bash
# Check firewall
sudo iptables -L | grep -E "170|171"

# Check if service is listening
sudo netstat -tuln | grep python

# Test local loopback
sudo python3 -c "
from raw_socket_server import *
start_raw_socket_threads()
time.sleep(1)
send_message('127.0.0.1', 'test')
time.sleep(1)
print(get_received_messages())
"
```

**File transfer fails**
```bash
# Check available disk space
df -h

# Check file permissions
ls -la shared_files/received/

# Monitor transfer progress
tail -f raw_socket.log
```

### Debug Mode
```python
import logging
logging.getLogger().setLevel(logging.DEBUG)
```

### Network Monitoring
```bash
# Monitor raw socket traffic
sudo tcpdump -i any -n proto 170

# Check system socket usage
sudo netstat -s | grep -i raw

# Monitor file descriptor usage
lsof -p $(pgrep python3)
```

## Architecture

### Protocol Design
- Uses custom IP protocols (170, 171) for direct communication
- Sequence numbers prevent duplicates and ensure ordering
- Acknowledgment system with exponential backoff retry
- Machine IDs prevent self-acknowledgment loops

### Threading Model
- **Receiver threads**: Listen for incoming packets (one per protocol)
- **Sender threads**: Process outgoing message and file queues
- **Retry thread**: Handles retransmission of unacknowledged packets

### File Transfer Process
1. File split into 4KB chunks and base64 encoded
2. Each chunk sent as separate packet with metadata
3. Receiver stores chunks in temporary directory
4. When complete, chunks reassembled into final file
5. Temporary files cleaned up automatically

## Development

### Running Tests
```bash
# Basic functionality test
sudo python3 -m pytest test_raw_socket.py

# Network stress test
sudo python3 stress_test.py

# Multi-peer test
sudo python3 multi_peer_test.py
```


## License

MIT License - see LICENSE file for details.

## Support

For issues and questions:
1. Check this README and troubleshooting section
2. Review `raw_socket.log` for error messages
3. Test with minimal setup (localhost first)
4. Report issues with system info and logs
