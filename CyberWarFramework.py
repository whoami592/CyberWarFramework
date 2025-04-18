# CyberWarFramework - A Python-based Cybersecurity Framework
# Created by Mr. Sabaz Ali Khan
# Purpose: Modular framework integrating multiple cybersecurity tools for network scanning, 
# vulnerability analysis, password cracking, and log analysis

import argparse
import sys
import socket
import scapy.all as scapy
import nmap
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import base64
import re
import getpass

class CyberWarFramework:
    def __init__(self):
        self.nm = nmap.PortScanner()

    def display_menu(self):
        """Display the main menu for the framework"""
        print("\n=== CyberWarFramework by Mr. Sabaz Ali Khan ===")
        print("1. Network Scanner (Port Scanning)")
        print("2. Vulnerability Scanner (Basic)")
        print("3. Password Cracker (Hash-based)")
        print("4. Log Analyzer (Basic Log Parsing)")
        print("5. Exit")
        choice = input("Enter your choice (1-5): ")
        return choice

    def network_scanner(self, target, port_range="1-1024"):
        """Perform a network scan using python-nmap"""
        try:
            print(f"\nScanning {target} for open ports ({port_range})...")
            self.nm.scan(target, port_range)
            for host in self.nm.all_hosts():
                print(f"\nHost: {host} ({self.nm[host].hostname()})")
                print(f"State: {self.nm[host].state()}")
                for proto in self.nm[host].all_protocols():
                    print(f"Protocol: {proto}")
                    ports = self.nm[host][proto].keys()
                    for port in sorted(ports):
                        state = self.nm[host][proto][port]['state']
                        print(f"Port: {port}\tState: {state}")
        except Exception as e:
            print(f"Error during network scan: {e}")

    def vulnerability_scanner(self, target):
        """Basic vulnerability scanner using Nmap scripting engine"""
        try:
            print(f"\nRunning vulnerability scan on {target}...")
            self.nm.scan(target, arguments="-sV --script=vuln")
            for host in self.nm.all_hosts():
                print(f"\nHost: {host}")
                if 'script' in self.nm[host]:
                    for script, output in self.nm[host]['script'].items():
                        print(f"Script: {script}\nOutput: {output}")
                else:
                    print("No vulnerabilities found or script output unavailable.")
        except Exception as e:
            print(f"Error during vulnerability scan: {e}")

    def password_cracker(self, hash_value, wordlist_path):
        """Basic password cracker for SHA-256 hashes"""
        try:
            print("\nStarting password cracking...")
            if not os.path.exists(wordlist_path):
                print(f"Wordlist file {wordlist_path} not found.")
                return

            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                for word in f:
                    word = word.strip()
                    digest = hashes.Hash(hashes.SHA256())
                    digest.update(word.encode('utf-8'))
                    hashed_word = digest.finalize().hex()
                    if hashed_word == hash_value:
                        print(f"Password found: {word}")
                        return
            print("Password not found in wordlist.")
        except Exception as e:
            print(f"Error during password cracking: {e}")

    def log_analyzer(self, log_file):
        """Basic log file analyzer to detect suspicious activity"""
        try:
            if not os.path.exists(log_file):
                print(f"Log file {log_file} not found.")
                return

            print(f"\nAnalyzing log file: {log_file}")
            suspicious_patterns = [
                r"failed login",
                r"unauthorized access",
                r"error.*authentication"
            ]

            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    for pattern in suspicious_patterns:
                        if re.search(pattern, line, re.IGNORECASE):
                            print(f"Suspicious entry found: {line.strip()}")
        except Exception as e:
            print(f"Error during log analysis: {e}")

    def run(self):
        """Main loop to run the framework"""
        while True:
            choice = self.display_menu()
            if choice == '1':
                target = input("Enter target IP or hostname: ")
                port_range = input("Enter port range (e.g., 1-1024) or press Enter for default: ") or "1-1024"
                self.network_scanner(target, port_range)
            elif choice == '2':
                target = input("Enter target IP or hostname: ")
                self.vulnerability_scanner(target)
            elif choice == '3':
                hash_value = input("Enter SHA-256 hash to crack: ")
                wordlist_path = input("Enter path to wordlist file: ")
                self.password_cracker(hash_value, wordlist_path)
            elif choice == '4':
                log_file = input("Enter path to log file: ")
                self.log_analyzer(log_file)
            elif choice == '5':
                print("Exiting CyberWarFramework. Goodbye!")
                sys.exit(0)
            else:
                print("Invalid choice. Please select a valid option.")

def main():
    parser = argparse.ArgumentParser(description="CyberWarFramework by Mr. Sabaz Ali Khan")
    parser.add_argument('--version', action='version', version='CyberWarFramework 1.0')
    args = parser.parse_args()

    framework = CyberWarFramework()
    print("Welcome to CyberWarFramework by Mr. Sabaz Ali Khan")
    framework.run()

if __name__ == "__main__":
    main()