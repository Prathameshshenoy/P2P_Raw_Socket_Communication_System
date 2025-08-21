# Raw Socket Communication System

A lightweight peer-to-peer protocol built on raw IP sockets, with reliable messaging and file transfer.

## Features
- Custom IP protocols (`170` for messages, `171` for files)  
- Reliable delivery (acks + retries)  
- File transfer with chunking + reassembly  
- Real-time messaging  
- Peer discovery  
- Built-in logging & recovery  

---

## Quick Start

1. **Clone & setup**
```bash
git clone https://github.com/Prathameshshenoy/P2P_Raw_Socket_Communication_System.git
cd raw-socket-communication
sudo python3 setup.py
```

2. **Start the server**
```bash
sudo python3 raw_socket_server.py
```

3. **Use the client**
```bash
sudo python3 client.py interactive
```

---

## Requirements
- Linux (recommended) / macOS  
- Python 3.6+  
- Root privileges (for raw sockets)  
- Firewall open for protocols **170-171**

---

## Usage

### Server (interactive)
```bash
sudo python3 raw_socket_server.py
```
Commands:  
- `send <ip> <msg>` – send a message  
- `file <ip> <path>` – send a file  
- `status` – system status  
- `messages` – check inbox  

### Client Library
```bash
sudo python3 client.py interactive
sudo python3 client.py example
sudo python3 client.py discover
```

### Programmatic
```python
from raw_socket_server import start_raw_socket_threads, send_message, get_received_messages

start_raw_socket_threads()
send_message("192.168.1.100", "Hello!", sender="me")

for src, msg in get_received_messages():
    print(f"{src}: {msg['content']}")
```

---

## API (Core Functions)

- `start_raw_socket_threads()` – start communication threads  
- `send_message(ip, text, sender="anon", channel_id="general")`  
- `send_file(source_ip, recipients, file_path, channel_id, sender)`  
- `get_received_messages(timeout=0.1)`  
- `get_system_status()`  
- `stop_system()`  

**Message format**
```python
{
  "content": "hi",
  "sender": "user",
  "channel_id": "general",
  "timestamp": "2024-01-01T12:00:00Z",
  "is_file": 0
}
```

---

## Configuration
In `raw_socket_server.py`:
```python
MESSAGE_PROTOCOL = 170
FILE_TRANSFER_PROTOCOL = 171
CHUNK_SIZE = 4096
MAX_RETRIES = 5
RETRY_TIMEOUT = 2.0
BACKOFF_FACTOR = 1.5
```

---

## Troubleshooting

- **"Operation not permitted"** → Run with `sudo`  
- **No messages** → Check firewall:  
  ```bash
  sudo iptables -L | grep -E "170|171"
  ```
- **File transfer fails** → Check disk space & permissions in `shared_files/received/`  

Enable debug logging:
```python
import logging
logging.getLogger().setLevel(logging.DEBUG)
```

---

## Advanced Usage

- **Firewall setup**
```bash
sudo iptables -A INPUT -p 170 -j ACCEPT
sudo iptables -A INPUT -p 171 -j ACCEPT
```

- **Network monitoring**
```bash
sudo tcpdump -i any -n proto 170 or proto 171
```

- **Testing between machines**
```bash
# On A (192.168.1.100):
send_message('192.168.1.101', 'Hello from A!')

# On B:
print(get_received_messages(timeout=2))
```

---

## License
MIT License – see LICENSE.
