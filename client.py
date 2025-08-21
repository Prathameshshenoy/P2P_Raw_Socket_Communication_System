#!/usr/bin/env python3
import time
import os
import sys
from pathlib import Path

try:
    from raw_socket_server import (
        start_raw_socket_threads, 
        send_message, 
        send_file, 
        get_received_messages, 
        get_system_status,
        get_local_ip,
        stop_system
    )
except ImportError:
    print("Error: raw_socket_server.py not found in the same directory")
    sys.exit(1)


class RawSocketClient:
    def __init__(self):
        self.running = False
        
    def start(self):
        if os.geteuid() != 0:
            print("Error: This program requires root privileges.")
            print("Please run with: sudo python3 client_example.py")
            return False
            
        print("Starting Raw Socket Client...")
        start_raw_socket_threads()
        time.sleep(2)
        
        status = get_system_status()
        if status['system_ready']:
            print(f"Client ready! Machine ID: {status['machine_id']}")
            print(f"Local IP: {status['local_ip']}")
            self.running = True
            return True
        else:
            print("Failed to start client")
            return False
    
    def send_text_message(self, dest_ip, message, sender="client_user"):
        return send_message(dest_ip, message, sender)
    
    def send_file_to_peer(self, dest_ip, file_path, sender="client_user"):
        if not Path(file_path).exists():
            print(f"File not found: {file_path}")
            return False
        return send_file(get_local_ip(), [(dest_ip, "peer")], file_path, "general", sender)
    
    def check_messages(self):
        return get_received_messages(timeout=0.5)
    
    def get_status(self):
        return get_system_status()
    
    def stop(self):
        self.running = False
        stop_system()


def interactive_mode():
    client = RawSocketClient()
    
    if not client.start():
        return
    
    print("\nInteractive Mode - Available commands:")
    print("  send <ip> <message>     - Send text message")
    print("  file <ip> <filepath>    - Send file")
    print("  check                   - Check for received messages")
    print("  status                  - Show system status")
    print("  help                    - Show this help")
    print("  quit                    - Exit")
    
    try:
        while client.running:
            try:
                cmd = input("\nclient> ").strip()
                if not cmd:
                    continue
                
                parts = cmd.split(' ', 2)
                command = parts[0].lower()
                
                if command == "quit" or command == "exit":
                    break
                elif command == "help":
                    print("Commands:")
                    print("  send <ip> <message>     - Send text message")
                    print("  file <ip> <filepath>    - Send file")
                    print("  check                   - Check for received messages")
                    print("  status                  - Show system status")
                    print("  quit                    - Exit")
                elif command == "send" and len(parts) >= 3:
                    ip = parts[1]
                    message = parts[2]
                    if client.send_text_message(ip, message):
                        print(f"Message sent to {ip}")
                    else:
                        print("Failed to send message")
                elif command == "file" and len(parts) >= 3:
                    ip = parts[1]
                    filepath = parts[2]
                    if client.send_file_to_peer(ip, filepath):
                        print(f"File queued for sending to {ip}")
                    else:
                        print("Failed to send file")
                elif command == "check":
                    messages = client.check_messages()
                    if messages:
                        print(f"Received {len(messages)} messages:")
                        for source, msg in messages:
                            if msg.get('is_file'):
                                print(f"  File from {source}: {msg.get('file_name')}")
                                print(f"    Saved to: {msg.get('file_path')}")
                            else:
                                print(f"  Message from {source}: {msg.get('content')}")
                    else:
                        print("No new messages")
                elif command == "status":
                    status = client.get_status()
                    print("System Status:")
                    for key, value in status.items():
                        print(f"  {key}: {value}")
                else:
                    print("Unknown command. Type 'help' for available commands.")
                    
            except KeyboardInterrupt:
                break
            except EOFError:
                break
                
    except KeyboardInterrupt:
        pass
    finally:
        print("\nShutting down client...")
        client.stop()


def example_usage():
    client = RawSocketClient()
    
    if not client.start():
        return
    
    print("\nRunning example usage...")
    
    try:
        other_ip = input("Enter IP address of another peer (or press Enter to skip): ").strip()
        
        if other_ip:
            print(f"\nSending test message to {other_ip}...")
            success = client.send_text_message(other_ip, "Hello from raw socket client!")
            if success:
                print("Message sent successfully")
            else:
                print("Failed to send message")
            
            test_file = "test_file.txt"
            with open(test_file, 'w') as f:
                f.write("This is a test file for raw socket transfer.\n")
                f.write(f"Created at: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            
            print(f"\nSending test file to {other_ip}...")
            success = client.send_file_to_peer(other_ip, test_file)
            if success:
                print("File queued for sending")
            else:
                print("Failed to queue file")
        
        print("\nListening for messages for 10 seconds...")
        for i in range(10):
            messages = client.check_messages()
            if messages:
                print(f"Received {len(messages)} messages:")
                for source, msg in messages:
                    print(f"  From {source}: {msg}")
            time.sleep(1)
            print(f"  Waiting... {10-i} seconds remaining")
        
        print("\nFinal status:")
        status = client.get_status()
        for key, value in status.items():
            print(f"  {key}: {value}")
            
    except KeyboardInterrupt:
        pass
    finally:
        client.stop()


def discover_peers():
    client = RawSocketClient()
    
    if not client.start():
        return
    
    print("\nPeer Discovery Mode")
    print("This will broadcast a discovery message to common IP ranges")
    local_ip = get_local_ip()
    ip_parts = local_ip.split('.')
    
    if len(ip_parts) == 4:
        base_ip = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}"
        print(f"Scanning {base_ip}.1-254 for peers...")
        
        discovery_message = f"DISCOVER:{local_ip}:rawsocket"
        active_peers = []
        
        for i in range(1, 255):
            target_ip = f"{base_ip}.{i}"
            if target_ip != local_ip:
                client.send_text_message(target_ip, discovery_message, "discovery")
        
        print("Discovery messages sent. Listening for responses...")
        
        for _ in range(30):
            messages = client.check_messages()
            for source, msg in messages:
                if msg.get('content', '').startswith('DISCOVER:'):
                    if source not in active_peers:
                        active_peers.append(source)
                        print(f"Found peer: {source}")
            time.sleep(0.5)
        
        print(f"\nDiscovered {len(active_peers)} peers:")
        for peer in active_peers:
            print(f"  {peer}")
    
    client.stop()


if __name__ == "__main__":
    if len(sys.argv) > 1:
        mode = sys.argv[1].lower()
        if mode == "interactive" or mode == "i":
            interactive_mode()
        elif mode == "example" or mode == "e":
            example_usage()
        elif mode == "discover" or mode == "d":
            discover_peers()
        else:
            print("Unknown mode. Available modes:")
            print("  python3 client_example.py interactive  - Interactive command mode")
            print("  python3 client_example.py example      - Run example usage")
            print("  python3 client_example.py discover     - Discover other peers")
    else:
        print("Raw Socket Client")
        print("================")
        print("Available modes:")
        print("  python3 client_example.py interactive  - Interactive command mode")
        print("  python3 client_example.py example      - Run example usage")
        print("  python3 client_example.py discover     - Discover other peers")
        print("\nNote: Requires root privileges (run with sudo)")