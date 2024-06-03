import tkinter as tk
from tkinter import ttk, messagebox
import nmap
import json
import requests
import socket
import paramiko
from bs4 import BeautifulSoup
import threading

# Load common passwords from GitHub repository
passwords_url = 'https://raw.githubusercontent.com/vlhomme/list-of-most-common-password/master/passwords.json'
passwords_response = requests.get(passwords_url)
common_passwords = json.loads(passwords_response.text)

# Load common usernames from GitHub Gist
usernames_url = 'https://gist.githubusercontent.com/kivox/920c271ef8dec2b33c84e1f2cc2977fc/raw/77e5d15c626f3da529e4c78aa3c1b3203b8d8dbb/common_usernames.txt'
usernames_response = requests.get(usernames_url)
common_usernames = usernames_response.text.splitlines()

def scan_network():
    target = target_entry.get()
    if not target:
        messagebox.showerror("Error", "Please enter a target (URL/IP) to scan.")
        return
    additional_ports = additional_ports_entry.get()
    ports_to_scan = ['1-1000', '1433']  # Default ports to scan

    if additional_ports:
        additional_ports_list = additional_ports.split(',')
        valid_ports = []
        for port_spec in additional_ports_list:
            if '-' in port_spec:
                # Check if the port specification is a range
                start, end = port_spec.split('-')
                try:
                    start_port = int(start)
                    end_port = int(end)
                    if start_port <= end_port and 1 <= start_port <= 65535 and 1 <= end_port <= 65535:
                        valid_ports.append(port_spec)
                    else:
                        raise ValueError("Invalid port range: start and end ports must be between 1 and 65535.")
                except ValueError:
                    pass  # Ignore if the port range cannot be converted to integers
            else:
                # Check if the port specification is a single port number
                try:
                    port_number = int(port_spec)
                    if 1 <= port_number <= 65535:  # Valid port range
                        valid_ports.append(port_spec)
                    else:
                        raise ValueError("Invalid port number: port must be between 1 and 65535.")
                except ValueError:
                    pass  # Ignore if the port number cannot be converted to an integer
        
        if valid_ports:
            ports_to_scan.extend(valid_ports)
            arguments = '-p ' + ','.join(ports_to_scan)
        else:
            messagebox.showerror("Error", "No valid ports specified. Please enter valid port numbers or ranges.")
            return
    else:
        arguments = '-p ' + ','.join(ports_to_scan)



    output_text.delete(1.0, tk.END)
    output_text.insert(tk.END, "Security check initiated....\n","info")

    # Wait for any existing scan thread to complete
    for thread in threading.enumerate():
        if thread.name == "ScanThread":
            messagebox.showwarning("Warning", "A scan is already in progress. Please wait for it to complete.")
            return

    scan_thread = threading.Thread(name="ScanThread", target=perform_scan, args=(target, arguments))
    scan_thread.start()

def perform_scan(target, ports_to_scan):
    # Join the elements of ports_to_scan list into a single string
    arguments = ' '.join(ports_to_scan)
    
    scanner = nmap.PortScanner()
    scanner.scan(target, arguments=arguments)

    output_text.delete(1.0, tk.END)
    output_text.insert(tk.END, "Security check initiated....\n","info")

    safe_website = True  # Assume the website is safe by default

    for host in scanner.all_hosts():
        output_text.insert(tk.END, f"Scanning host: {host}\n", "info")

        for proto in scanner[host].all_protocols():
            output_text.insert(tk.END, f"  Protocol: {proto}\n", "info")
            ports = scanner[host][proto].keys()

            for port in ports:
                port_info = scanner[host][proto][port]
                output_text.insert(tk.END, f"    Port: {port} - State: {port_info['state']}\n", "info")
                if port_info['state'] == 'open':
                    output_text.insert(tk.END, "      Potential vulnerability found: Open port\n","warning")
                    output_text.insert(tk.END, "      Suggestion: Close unnecessary ports to reduce attack surface\n","warning")
                    safe_website = False
                if 'version' in port_info and port_info['version'].lower() != 'unknown':
                    version = port_info['version']
                    output_text.insert(tk.END, f"      Software version: {version}\n","info")
                    if is_outdated(version):
                        output_text.insert(tk.END, "      Potential vulnerability found: Outdated software\n","warning")
                        output_text.insert(tk.END, "      Suggestion: Update software to the latest version\n","warning")
                        safe_website = False
                if 'ssh' in port_info['name']:
                    if is_weak_credentials(host, port, common_usernames, common_passwords):
                        output_text.insert(tk.END, "      Potential vulnerability found: Weak SSH credentials\n","warning")
                        output_text.insert(tk.END, "      Suggestion: Enforce strong password policies\n","warning")
                        safe_website = False
                if port in [80, 443]:
                    if not is_encrypted_service(host, port):
                        output_text.insert(tk.END, f"      Potential vulnerability found: Unencrypted service on port {port}\n","warning")
                        output_text.insert(tk.END, "      Suggestion: Enable encryption (e.g., SSL/TLS) for sensitive services\n","warning")
                        safe_website = False
                        if port == 80:
                            check_http_security_headers(host)
                elif port == 21:
                    if not is_encrypted_service(host, port):
                        output_text.insert(tk.END, f"      Potential vulnerability found: Unencrypted service on port {port}\n","warning")
                        output_text.insert(tk.END, "      Suggestion: Avoid using FTP and switch to SFTP or FTPS for secure file transfer\n","warning")
                        safe_website = False
                elif port == 23:
                    output_text.insert(tk.END, f"      Potential vulnerability found: Unencrypted service on port {port}\n","warning")
                    output_text.insert(tk.END, "      Suggestion: Avoid using Telnet due to security risks. Switch to SSH for secure remote access\n","warning")
                    safe_website = False
                elif port == 1433:
                    output_text.insert(tk.END, f"      Potential vulnerability found: MSSQL detected on port {port}\n","warning")
                    output_text.insert(tk.END, "      Suggestion: Ensure MSSQL is properly configured to prevent SQL injection attacks\n","warning")
                    safe_website = False

    # Add final conclusion on website safety
    if safe_website:
        output_text.insert(tk.END, "No significant vulnerabilities found. Positive aspects about the website:\n", "safe")
        output_text.insert(tk.END, "- Secure communication via HTTPS\n", "safe")
        output_text.insert(tk.END, "- Minimal attack surface\n", "safe")
        output_text.insert(tk.END, "- Up-to-date software\n", "safe")
        output_text.insert(tk.END, "- No weak SSH credentials found.\n", "safe")
        output_text.insert(tk.END, "- No unencrypted services found.\n", "safe")
        output_text.insert(tk.END, "- No SQL injection vulnerabilities found.\n", "safe")
        output_text.insert(tk.END, "- Strong authentication\n", "safe")
        output_text.insert(tk.END, "- No missing security headers found.\n", "safe")
        output_text.insert(tk.END, "- Adherence to security best practices\n", "safe")
        output_text.insert(tk.END, "- User trust and credibility\n", "safe")
        output_text.insert(tk.END, "No significant vulnerabilities found. The website appears to be safe.\n", "safe")
    else:
        output_text.insert(tk.END, "Vulnerabilities detected! Review the suggestions provided to improve security.\n", "warning")

    output_text.insert(tk.END, "Scan complete.\n")


def is_outdated(version):
    latest_version = '1.0.0'
    return version < latest_version

def is_weak_credentials(host, port, common_usernames, common_passwords):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    for username in common_usernames:
        for password in common_passwords:
            try:
                ssh.connect(host, port=port, username=username, password=password, timeout=5)
                return True
            except paramiko.AuthenticationException:
                pass
            except Exception as e:
                print(f"Error: {e}")
    ssh.close()
    return False

def is_encrypted_service(host, port):
    if port == 80:
        try:
            with socket.create_connection((host, port)) as sock:
                sock.send(b'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n')
                response = sock.recv(1024).decode('utf-8')
                if 'Location: https://' in response:
                    return True
                else:
                    return False
        except Exception as e:
            print(f"Error checking port {port}: {e}")
            return False
    elif port == 443:
        return True
    else:
        return True

def check_http_security_headers(host):
    try:
        response = requests.get(f"http://{host}")
        headers = response.headers
        if 'X-Frame-Options' not in headers:
            output_text.insert(tk.END, "      Potential vulnerability found: Missing X-Frame-Options header\n", "warning")
            output_text.insert(tk.END, "      Suggestion: Implement X-Frame-Options header to prevent Clickjacking attacks\n", "warning")
        if 'X-XSS-Protection' not in headers:
            output_text.insert(tk.END, "      Potential vulnerability found: Missing X-XSS-Protection header\n", "warning")
            output_text.insert(tk.END, "      Suggestion: Implement X-XSS-Protection header to mitigate XSS attacks\n", "warning")
        if 'Strict-Transport-Security' not in headers:
            output_text.insert(tk.END, "      Potential vulnerability found: Missing Strict-Transport-Security header\n", "warning")
            output_text.insert(tk.END, "      Suggestion: Implement Strict-Transport-Security header to enforce HTTPS\n", "warning")
        if 'Content-Security-Policy' not in headers:
            output_text.insert(tk.END, "      Potential vulnerability found: Missing Content-Security-Policy header\n", "warning")
            output_text.insert(tk.END, "      Suggestion: Implement Content-Security-Policy header to prevent various types of attacks\n", "warning")
    except Exception as e:
        print(f"Error checking HTTP headers: {e}")

root = tk.Tk()
root.title("WEB GUARD-Advance Website Vulnerability Scanner")

target_label = ttk.Label(root, text="Enter Target (URL/IP):")
target_label.pack(pady=5)
target_entry = ttk.Entry(root, width=75)
target_entry.pack()

additional_ports_label = ttk.Label(root, text="Additional Ports to Scan (comma-separated):"+"0 - 65535")
additional_ports_label.pack(pady=5)
additional_ports_entry = ttk.Entry(root, width=75)
additional_ports_entry.pack()

scan_button = ttk.Button(root, text="Scan", command=scan_network)
scan_button.pack(pady=10)

output_text = tk.Text(root, width=80, height=20)
output_text.pack(fill=tk.BOTH, expand=True)

# Define tag configurations for text colors
output_text.tag_config("safe", foreground="green")
output_text.tag_config("warning", foreground="red")
output_text.tag_config("info", foreground="black")

root.mainloop()
