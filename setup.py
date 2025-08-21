#!/usr/bin/env python3
import os
import sys
import subprocess
import platform
from pathlib import Path


def check_root():
    if os.geteuid() != 0:
        print("Setup requires root privileges for system configuration.")
        print("Please run: sudo python3 setup.py")
        return False
    return True


def check_python_version():
    if sys.version_info < (3, 6):
        print("Python 3.6 or higher is required")
        return False
    print(f"Python version: {sys.version}")
    return True


def create_directories():
    dirs = ['shared_files/received', 'shared_files/sent', 'logs']
    for dir_path in dirs:
        Path(dir_path).mkdir(parents=True, exist_ok=True)
        print(f"Created directory: {dir_path}")


def configure_firewall():
    system = platform.system().lower()
    
    if system == 'linux':
        print("Configuring firewall for Linux...")
        commands = [
            ['iptables', '-A', 'INPUT', '-p', '170', '-j', 'ACCEPT'],
            ['iptables', '-A', 'INPUT', '-p', '171', '-j', 'ACCEPT'],
            ['iptables', '-A', 'OUTPUT', '-p', '170', '-j', 'ACCEPT'],
            ['iptables', '-A', 'OUTPUT', '-p', '171', '-j', 'ACCEPT']
        ]
        
        for cmd in commands:
            try:
                result = subprocess.run(cmd, capture_output=True, text=True)
                if result.returncode == 0:
                    print(f"Success: {' '.join(cmd)}")
                else:
                    print(f"Warning: {' '.join(cmd)} failed - {result.stderr}")
            except FileNotFoundError:
                print("iptables not found - firewall configuration skipped")
                break
                
    elif system == 'darwin':
        print("macOS detected - manual firewall configuration may be required")
        print("You may need to allow protocols 170 and 171 in System Preferences > Security & Privacy > Firewall")
    else:
        print(f"Unknown system {system} - manual firewall configuration required")


def test_raw_socket():
    try:
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, 170)
        sock.close()
        print("Raw socket test: PASSED")
        return True
    except socket.error as e:
        print(f"Raw socket test: FAILED - {e}")
        return False


def create_service_file():
    service_content = """[Unit]
Description=Raw Socket Communication Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/raw-socket-comm
ExecStart=/usr/bin/python3 /opt/raw-socket-comm/raw_socket_server.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
"""
    
    service_path = Path('/etc/systemd/system/raw-socket-comm.service')
    try:
        service_path.write_text(service_content)
        print(f"Created systemd service file: {service_path}")
        
        subprocess.run(['systemctl', 'daemon-reload'], check=True)
        print("Systemd daemon reloaded")
        
        print("To enable auto-start: sudo systemctl enable raw-socket-comm")
        print("To start service: sudo systemctl start raw-socket-comm")
        
    except Exception as e:
        print(f"Failed to create service file: {e}")


def install_to_system():
    install_path = Path('/opt/raw-socket-comm')
    current_path = Path.cwd()
    
    try:
        if install_path.exists():
            import shutil
            shutil.rmtree(install_path)
            
        install_path.mkdir(parents=True)
        
        files_to_copy = [
            'raw_socket_server.py',
            'client_example.py',
            'README.md'
        ]
        
        for filename in files_to_copy:
            src = current_path / filename
            if src.exists():
                import shutil
                shutil.copy2(src, install_path / filename)
                print(f"Installed: {filename}")
        
        (install_path / 'shared_files').mkdir(exist_ok=True)
        (install_path / 'shared_files' / 'received').mkdir(exist_ok=True)
        
        os.chmod(install_path / 'raw_socket_server.py', 0o755)
        os.chmod(install_path / 'client_example.py', 0o755)
        
        print(f"System installation completed at {install_path}")
        
    except Exception as e:
        print(f"System installation failed: {e}")


def main():
    print("Raw Socket Communication Setup")
    print("==============================")
    
    if not check_root():
        return 1
        
    if not check_python_version():
        return 1
    
    print("\n1. Creating directories...")
    create_directories()
    
    print("\n2. Testing raw socket capability...")
    if not test_raw_socket():
        print("Raw socket test failed - check system permissions and kernel support")
        response = input("Continue anyway? (y/N): ").lower()
        if response != 'y':
            return 1
    
    print("\n3. Configuring firewall...")
    configure_firewall()
    
    install_choice = input("\n4. Install to system location (/opt/raw-socket-comm)? (y/N): ").lower()
    if install_choice == 'y':
        install_to_system()
        
        service_choice = input("\n5. Create systemd service for auto-start? (y/N): ").lower()
        if service_choice == 'y':
            create_service_file()
    
    print("\nSetup completed!")
    print("\nNext steps:")
    print("1. Run server: sudo python3 raw_socket_server.py")
    print("2. Or run client: sudo python3 client_example.py interactive")
    print("3. Check logs in raw_socket.log for troubleshooting")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())