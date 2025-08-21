#!/usr/bin/env python3
import socket
import struct
import threading
import queue
import json
import time
import base64
import os
import sys
from pathlib import Path
import shutil
from datetime import datetime
from typing import Dict, Tuple, List, Optional, Any
import logging

MESSAGE_PROTOCOL = 170
FILE_TRANSFER_PROTOCOL = 171
CHUNK_SIZE = 4096
MAX_RETRIES = 5
RETRY_TIMEOUT = 2.0
BACKOFF_FACTOR = 1.5

machine_id = os.urandom(4).hex()
next_sequence_number = 0

message_queue_to_send = queue.Queue()
received_message_queue = queue.Queue()
file_transfer_queue_to_send = queue.Queue()
received_file_transfer_queue = queue.Queue()

sent_packets: Dict[Tuple[str, int, int], Dict[str, Any]] = {}
acknowledgement_received: Dict[Tuple[str, int, int], float] = {}
processed_packets = set()

RECEIVED_FILES_DIR = Path('shared_files/received')
RECEIVED_FILES_DIR.mkdir(parents=True, exist_ok=True)

_system_ready = threading.Event()
_shutdown_event = threading.Event()

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('raw_socket.log', mode='a')
    ]
)
logger = logging.getLogger(__name__)


def create_raw_socket(protocol: int) -> Optional[socket.socket]:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, protocol)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        sock.settimeout(1.0)
        logger.debug(f"Raw socket created for protocol {protocol}")
        return sock
    except socket.error as e:
        logger.error(f"Error creating raw socket for protocol {protocol}: {e}")
        return None


def craft_ip_header(source_ip: str, dest_ip: str, protocol: int, payload_length: int) -> bytes:
    version = 4
    ihl = 5
    tos = 0
    total_length = ihl * 4 + payload_length
    identification = 54321
    flags = 0
    fragment_offset = 0
    ttl = 255
    checksum = 0
    
    try:
        source_address = socket.inet_aton(source_ip)
        dest_address = socket.inet_aton(dest_ip)
    except socket.error as e:
        logger.error(f"Invalid IP address: {e}")
        raise

    ip_header = struct.pack('!BBHHHBBH4s4s',
                           (version << 4) + ihl, tos, socket.htons(total_length),
                           identification, (flags << 13) + fragment_offset,
                           ttl, protocol, checksum, source_address, dest_address)

    checksum = calculate_checksum(ip_header)
    ip_header = struct.pack('!BBHHHBBH4s4s',
                           (version << 4) + ihl, tos, socket.htons(total_length),
                           identification, (flags << 13) + fragment_offset,
                           ttl, protocol, checksum, source_address, dest_address)
    
    return ip_header


def calculate_checksum(data: bytes) -> int:
    s = 0
    n = len(data) % 2
    
    for i in range(0, len(data) - n, 2):
        s += (data[i] + (data[i+1] << 8))
    
    if n:
        s += data[len(data) - 1]
    
    while (s >> 16):
        s = (s & 0xFFFF) + (s >> 16)
    
    s = ~s & 0xFFFF
    return socket.htons(s)


def get_local_ip() -> str:
    try:
        interfaces = []
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            primary_ip = s.getsockname()[0]
            interfaces.append(primary_ip)
        
        if primary_ip != "127.0.0.1":
            return primary_ip
        
        hostname = socket.gethostname()
        return socket.gethostbyname(hostname)
        
    except socket.error:
        return "127.0.0.1"


def send_raw_packet(source_ip: str, dest_ip: str, protocol: int, 
                   data: bytes, packet_type: str = "message", 
                   details: Optional[Dict] = None) -> int:
    global next_sequence_number, machine_id
    
    sequence_number = next_sequence_number
    next_sequence_number += 1

    try:
        if isinstance(data, bytes):
            data_obj = json.loads(data.decode('utf-8'))
        else:
            data_obj = json.loads(data) if isinstance(data, str) else data
    except (json.JSONDecodeError, UnicodeDecodeError):
        logger.error("Invalid data format for packet")
        return -1

    payload_data = {
        "sequence_number": sequence_number,
        "type": packet_type,
        "data": data_obj,
        "details": details or {},
        "machine_id": machine_id,
        "original_sequence": sequence_number
    }
    
    payload = json.dumps(payload_data).encode('utf-8')
    
    try:
        ip_header = craft_ip_header(source_ip, dest_ip.strip(), protocol, len(payload))
    except Exception as e:
        logger.error(f"Failed to craft IP header: {e}")
        return -1
    
    packet = ip_header + payload
    
    sock = create_raw_socket(protocol)
    if not sock:
        return -1
        
    try:
        dest_address = (dest_ip.strip(), 0)
        sock.sendto(packet, dest_address)
        logger.debug(f"Sent packet (seq: {sequence_number}) to {dest_ip.strip()}")
        
        key = (dest_ip.strip(), sequence_number, protocol)
        sent_packets[key] = {
            "timestamp": time.time(),
            "type": packet_type,
            "data": data,
            "details": details,
            "original_sequence": sequence_number
        }
        
    except socket.error as e:
        logger.error(f"Error sending packet (seq: {sequence_number}): {e}")
        return -1
    finally:
        sock.close()
    
    return sequence_number


def send_acknowledgement(sock: socket.socket, source_ip: str, protocol: int,
                        original_sequence: int, original_type: str,
                        details: Optional[Dict] = None, 
                        original_machine_id: Optional[str] = None) -> None:
    global next_sequence_number, machine_id
    
    sequence_number = next_sequence_number
    next_sequence_number += 1
    
    ack_message = {
        "sequence_number": sequence_number,
        "type": "acknowledgement",
        "original_sequence": original_sequence,
        "original_type": original_type,
        "original_machine_id": original_machine_id,
        "status": "received",
        "details": details or {},
        "machine_id": machine_id
    }

    payload = json.dumps(ack_message).encode('utf-8')
    source_ip_local = get_local_ip()
    
    try:
        ip_header = craft_ip_header(source_ip_local, source_ip.strip(), protocol, len(payload))
        packet = ip_header + payload
        sock.sendto(packet, (source_ip.strip(), 0))
        logger.debug(f"Sent acknowledgment for packet {original_sequence}")
    except Exception as e:
        logger.error(f"Error sending acknowledgment: {e}")


def handle_file_chunk(source_address: str, file_data: str, details: Dict) -> None:
    try:
        file_id = details.get("file_id")
        file_name = details.get("file_name")
        chunk_index = details.get("chunk_index")
        total_chunks = details.get("total_chunks")
        channel_id = details.get("channel_id")
        sender = details.get("sender")

        if not all([file_id, file_name, chunk_index is not None, total_chunks]):
            logger.error("Missing file transfer details")
            return

        transfer_dir = RECEIVED_FILES_DIR / file_id
        transfer_dir.mkdir(parents=True, exist_ok=True)

        chunk_path = transfer_dir / f"chunk_{chunk_index}"
        try:
            chunk_bytes = base64.b64decode(file_data)
            chunk_path.write_bytes(chunk_bytes)
        except Exception as e:
            logger.error(f"Error writing chunk {chunk_index}: {e}")
            return

        logger.info(f"Received chunk {chunk_index}/{total_chunks} for {file_name}")

        received_chunks = len([f for f in transfer_dir.iterdir() 
                              if f.name.startswith("chunk_")])

        if received_chunks == total_chunks:
            logger.info(f"All chunks received for {file_name}, assembling...")
            
            final_file_path = RECEIVED_FILES_DIR / file_name
            counter = 1
            while final_file_path.exists():
                name_parts = file_name.rsplit('.', 1)
                if len(name_parts) == 2:
                    final_file_path = RECEIVED_FILES_DIR / f"{name_parts[0]}_{counter}.{name_parts[1]}"
                else:
                    final_file_path = RECEIVED_FILES_DIR / f"{file_name}_{counter}"
                counter += 1

            try:
                with final_file_path.open('wb') as output_file:
                    for i in range(total_chunks):
                        chunk_path = transfer_dir / f"chunk_{i}"
                        if chunk_path.exists():
                            output_file.write(chunk_path.read_bytes())

                file_message = {
                    "sender": sender,
                    "channel_id": channel_id,
                    "content": f"Shared a file: {final_file_path.name}",
                    "is_file": 1,
                    "file_path": str(final_file_path),
                    "file_name": final_file_path.name,
                    "file_id": file_id,
                    "timestamp": datetime.utcnow().isoformat() + "Z"
                }
                
                received_message_queue.put((source_address, file_message))
                shutil.rmtree(transfer_dir)
                logger.info(f"File {final_file_path.name} successfully reconstructed")
                
            except Exception as e:
                logger.error(f"Error assembling file: {e}")
            
    except Exception as e:
        logger.error(f"Error handling file chunk: {e}")


def receive_raw_packets(received_queue: queue.Queue, protocol: int) -> None:
    logger.info(f"Started packet receiver thread for protocol {protocol}")
    
    while not _shutdown_event.is_set():
        sock = create_raw_socket(protocol)
        if not sock:
            logger.error(f"Failed to create socket for protocol {protocol}")
            time.sleep(5)
            continue
        
        try:
            while not _shutdown_event.is_set():
                try:
                    packet, addr = sock.recvfrom(65535)
                    
                    if len(packet) < 20:
                        continue
                        
                    ip_header_length = (packet[0] & 0x0F) * 4
                    if ip_header_length < 20 or ip_header_length > len(packet):
                        continue
                        
                    ip_header = packet[:ip_header_length]
                    payload = packet[ip_header_length:]

                    if len(payload) > 0:
                        iph = struct.unpack('!BBHHHBBH4s4s', ip_header[:20])
                        source_address = socket.inet_ntoa(iph[8]).strip()
                        received_protocol = iph[6]

                        if received_protocol == protocol:
                            process_received_packet(sock, source_address, payload, 
                                                  protocol, received_queue)
                            
                except socket.timeout:
                    continue
                except Exception as e:
                    logger.error(f"Error in receive loop: {e}")
                    time.sleep(0.1)
                    
        except socket.error as e:
            logger.error(f"Socket error in receiver: {e}")
        finally:
            sock.close()
            
        if not _shutdown_event.is_set():
            time.sleep(1)


def process_received_packet(sock: socket.socket, source_address: str, 
                           payload: bytes, protocol: int, 
                           received_queue: queue.Queue) -> None:
    try:
        received_data = json.loads(payload.decode('utf-8'))
        packet_type = received_data.get("type")
        sequence_number = received_data.get("sequence_number")
        sender_machine_id = received_data.get("machine_id", "unknown")
        actual_data = received_data.get("data")
        details = received_data.get("details")

        if sequence_number is None:
            logger.warning(f"Received packet with missing sequence number from {source_address}")
            return

        packet_identifier = (source_address, sequence_number, protocol, sender_machine_id)
        
        if packet_identifier not in processed_packets:
            processed_packets.add(packet_identifier)

            if packet_type == "acknowledgement":
                handle_acknowledgment(received_data, source_address, protocol)
            elif actual_data:
                logger.debug(f"Received {packet_type} packet from {source_address}")
                
                send_acknowledgement(sock, source_address, protocol, 
                                   sequence_number, packet_type, details, sender_machine_id)

                if packet_type == "file_chunk":
                    handle_file_chunk(source_address, actual_data, details)
                elif packet_type == "message":
                    received_queue.put((source_address, actual_data))
        else:
            if packet_type != "acknowledgement":
                send_acknowledgement(sock, source_address, protocol, 
                                   sequence_number, packet_type, details, sender_machine_id)

    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        logger.error(f"Decode error from {source_address}: {e}")
    except Exception as e:
        logger.error(f"Error processing packet: {e}")


def handle_acknowledgment(ack_data: Dict, source_address: str, protocol: int) -> None:
    original_sequence = ack_data.get("original_sequence")
    original_machine_id = ack_data.get("original_machine_id")
    
    if original_machine_id == machine_id:
        ack_key = (source_address, original_sequence, protocol)
        acknowledgement_received[ack_key] = time.time()
        logger.debug(f"Received ACK for packet {original_sequence} from {source_address}")
        
        if ack_key in sent_packets:
            del sent_packets[ack_key]


def process_message_queue() -> None:
    logger.info("Message processing thread started")
    
    while not _shutdown_event.is_set():
        try:
            source_ip, dest_ip, message_data = message_queue_to_send.get(timeout=1)
            if source_ip and dest_ip and message_data:
                payload = json.dumps(message_data).encode('utf-8')
                send_raw_packet(source_ip, dest_ip, MESSAGE_PROTOCOL, 
                               payload, "message", 
                               {"channel_id": message_data.get("channel_id")})
            message_queue_to_send.task_done()
        except queue.Empty:
            continue
        except Exception as e:
            logger.error(f"Error in message queue processing: {e}")


def process_file_transfer_queue() -> None:
    logger.info("File transfer processing thread started")
    
    while not _shutdown_event.is_set():
        try:
            source_ip, dest_ip, file_data, transfer_details = file_transfer_queue_to_send.get(timeout=1)
            if source_ip and dest_ip and file_data:
                payload = json.dumps(file_data).encode('utf-8')
                send_raw_packet(source_ip, dest_ip, FILE_TRANSFER_PROTOCOL, 
                               payload, "file_chunk", transfer_details)
            file_transfer_queue_to_send.task_done()
        except queue.Empty:
            continue
        except Exception as e:
            logger.error(f"Error in file transfer queue processing: {e}")


def send_file(source_ip: str, recipients: List[Tuple[str, str]], 
              file_path: str, channel_id: str, sender: str, 
              file_id: Optional[str] = None) -> bool:
    try:
        file_path = Path(file_path)
        if not file_path.exists():
            logger.error(f"File not found: {file_path}")
            return False

        if not file_id:
            file_id = f"transfer_{int(time.time())}_{os.urandom(4).hex()}"

        file_name = file_path.name
        file_size = file_path.stat().st_size

        if file_size == 0:
            logger.error("Cannot send empty file")
            return False

        file_data = file_path.read_bytes()
        total_chunks = (file_size + CHUNK_SIZE - 1) // CHUNK_SIZE
        logger.info(f"Sending {file_name} ({file_size} bytes) in {total_chunks} chunks")

        for chunk_index in range(total_chunks):
            start_pos = chunk_index * CHUNK_SIZE
            end_pos = min(start_pos + CHUNK_SIZE, file_size)
            chunk = file_data[start_pos:end_pos]

            chunk_data = base64.b64encode(chunk).decode('utf-8')
            transfer_details = {
                "file_id": file_id,
                "file_name": file_name,
                "chunk_index": chunk_index,
                "total_chunks": total_chunks,
                "channel_id": channel_id,
                "sender": sender
            }

            for recipient_ip, recipient_id in recipients:
                file_transfer_queue_to_send.put((source_ip, recipient_ip.strip(), 
                                                chunk_data, transfer_details))

        logger.info(f"All chunks for {file_name} queued for sending")
        return True
        
    except Exception as e:
        logger.error(f"Error sending file: {e}")
        return False


def resend_unacknowledged_packets() -> None:
    logger.info("Packet retry thread started")
    retry_counts = {}
    
    while not _shutdown_event.is_set():
        try:
            current_time = time.time()
            packets_to_resend = []
            
            for key, packet_info in list(sent_packets.items()):
                dest_ip, sequence_number, protocol = key
                sent_time = packet_info["timestamp"]
                
                if key in acknowledgement_received:
                    if key in retry_counts:
                        del retry_counts[key]
                    if key in sent_packets:
                        del sent_packets[key]
                    continue
                
                retry_count = retry_counts.get(key, 0)
                timeout = RETRY_TIMEOUT * (BACKOFF_FACTOR ** retry_count)
                
                if current_time - sent_time > timeout:
                    if retry_count >= MAX_RETRIES:
                        logger.warning(f"Max retries reached for packet {sequence_number} to {dest_ip}")
                        if key in retry_counts:
                            del retry_counts[key]
                        if key in sent_packets:
                            del sent_packets[key]
                    else:
                        packets_to_resend.append((key, packet_info))
                        retry_counts[key] = retry_count + 1
            
            for (dest_ip, sequence_number, protocol), packet_info in packets_to_resend:
                packet_type = packet_info["type"]
                original_data = packet_info.get("data")
                details = packet_info.get("details", {})
                
                logger.info(f"Resending {packet_type} packet to {dest_ip} (attempt {retry_counts[(dest_ip, sequence_number, protocol)]})")
                
                if packet_type in ["message", "file_chunk"] and original_data:
                    source_ip = get_local_ip()
                    send_raw_packet(source_ip, dest_ip, protocol, original_data, 
                                   packet_type, details)
            
            time.sleep(0.5)
            
        except Exception as e:
            logger.error(f"Error in resend thread: {e}")
            time.sleep(1)


def start_raw_socket_threads() -> None:
    logger.info("Starting raw socket threads...")
    
    threads = []
    
    receive_thread_chat = threading.Thread(
        target=receive_raw_packets, 
        args=(received_message_queue, MESSAGE_PROTOCOL), 
        daemon=True
    )
    receive_thread_chat.start()
    threads.append(receive_thread_chat)
    
    receive_thread_files = threading.Thread(
        target=receive_raw_packets, 
        args=(received_file_transfer_queue, FILE_TRANSFER_PROTOCOL), 
        daemon=True
    )
    receive_thread_files.start()
    threads.append(receive_thread_files)
    
    send_thread_chat = threading.Thread(target=process_message_queue, daemon=True)
    send_thread_chat.start()
    threads.append(send_thread_chat)
    
    send_thread_files = threading.Thread(target=process_file_transfer_queue, daemon=True)
    send_thread_files.start()
    threads.append(send_thread_files)
    
    retry_thread = threading.Thread(target=resend_unacknowledged_packets, daemon=True)
    retry_thread.start()
    threads.append(retry_thread)
    
    time.sleep(1)
    _system_ready.set()
    logger.info("All threads started successfully")
    
    return threads


def stop_system() -> None:
    logger.info("Stopping raw socket system...")
    _shutdown_event.set()
    time.sleep(1)


def send_message(dest_ip: str, message: str, sender: str = "anonymous", channel_id: str = "general") -> bool:
    if not _system_ready.is_set():
        logger.error("System not ready")
        return False
        
    source_ip = get_local_ip()
    message_data = {
        "content": message,
        "sender": sender,
        "channel_id": channel_id,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }
    
    try:
        message_queue_to_send.put((source_ip, dest_ip, message_data), timeout=1)
        return True
    except queue.Full:
        logger.error("Message queue full")
        return False


def get_received_messages(timeout: float = 0.1) -> List[Tuple[str, Dict]]:
    messages = []
    end_time = time.time() + timeout
    
    while time.time() < end_time:
        try:
            source, message = received_message_queue.get(timeout=0.1)
            messages.append((source, message))
            received_message_queue.task_done()
        except queue.Empty:
            break
    
    return messages


def get_system_status() -> Dict[str, Any]:
    return {
        "machine_id": machine_id,
        "local_ip": get_local_ip(),
        "system_ready": _system_ready.is_set(),
        "pending_messages": message_queue_to_send.qsize(),
        "pending_files": file_transfer_queue_to_send.qsize(),
        "unacknowledged_packets": len(sent_packets),
        "processed_packets": len(processed_packets)
    }


def main():
    print("Raw Socket Communication Server")
    print("===============================")
    status = get_system_status()
    print(f"Machine ID: {status['machine_id']}")
    print(f"Local IP: {status['local_ip']}")
    print(f"Message Protocol: {MESSAGE_PROTOCOL}")
    print(f"File Transfer Protocol: {FILE_TRANSFER_PROTOCOL}")
    print(f"Received Files Directory: {RECEIVED_FILES_DIR}")
    print("\nStarting server threads...")
    
    try:
        start_raw_socket_threads()
        print("Server running. Commands:")
        print("  send <ip> <message>")
        print("  file <ip> <filepath>")
        print("  status")
        print("  quit")
        
        while True:
            try:
                cmd = input("\n> ").strip()
                if not cmd:
                    continue
                    
                parts = cmd.split(' ', 2)
                
                if parts[0] == "quit":
                    break
                elif parts[0] == "status":
                    status = get_system_status()
                    for key, value in status.items():
                        print(f"  {key}: {value}")
                elif parts[0] == "send" and len(parts) >= 3:
                    ip = parts[1]
                    message = parts[2]
                    if send_message(ip, message):
                        print(f"Message sent to {ip}")
                    else:
                        print("Failed to send message")
                elif parts[0] == "file" and len(parts) >= 3:
                    ip = parts[1]
                    filepath = parts[2]
                    if send_file(get_local_ip(), [(ip, "user")], filepath, "general", "admin"):
                        print(f"File queued for sending to {ip}")
                    else:
                        print("Failed to send file")
                elif parts[0] == "messages":
                    messages = get_received_messages(timeout=0.5)
                    if messages:
                        print(f"Received {len(messages)} messages:")
                        for source, msg in messages:
                            print(f"  From {source}: {msg}")
                    else:
                        print("No messages received")
                else:
                    print("Unknown command")
                    
            except KeyboardInterrupt:
                break
            except EOFError:
                break
                
    except KeyboardInterrupt:
        pass
    finally:
        print("\nShutting down...")
        stop_system()


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Error: This program requires root privileges to create raw sockets.")
        print("Please run with: sudo python3 raw_socket_server.py")
        sys.exit(1)
    main()