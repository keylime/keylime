#!/usr/bin/env python3
"""
Test script to verify tenant can connect to registrar on the correct port
"""
import socket
import sys
import configparser

def test_port_connection(host, port):
    """Test if a port is accessible"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception as e:
        print(f"Error testing port {port}: {e}")
        return False

def read_tenant_config():
    """Read tenant configuration to check registrar settings"""
    config = configparser.ConfigParser()
    try:
        config.read('config-override/tenant.conf')
        registrar_ip = config.get('tenant', 'registrar_ip', fallback='localhost')
        registrar_port = config.getint('tenant', 'registrar_port', fallback=8881)
        return registrar_ip, registrar_port
    except Exception as e:
        print(f"Error reading config: {e}")
        return None, None

def main():
    print("Testing Keylime tenant-registrar connection configuration...")
    
    # Read current tenant configuration
    registrar_ip, registrar_port = read_tenant_config()
    if registrar_ip is None:
        print("❌ Failed to read tenant configuration")
        return 1
    
    print(f"📄 Tenant config: registrar_ip={registrar_ip}, registrar_port={registrar_port}")
    
    # Test connection to configured registrar port
    print(f"🔍 Testing connection to {registrar_ip}:{registrar_port}...")
    
    # Convert container name to localhost for testing from host
    test_host = 'localhost' if registrar_ip == 'keylime-registrar' else registrar_ip
    
    if test_port_connection(test_host, registrar_port):
        print(f"✅ Successfully connected to registrar on port {registrar_port}")
        print("✅ Configuration fix appears to be working!")
        return 0
    else:
        print(f"❌ Failed to connect to registrar on port {registrar_port}")
        print("❌ Port connection failed")
        return 1

if __name__ == "__main__":
    sys.exit(main())
