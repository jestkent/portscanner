import customtkinter as ctk
import socket
import threading
from datetime import datetime
import queue # For thread-safe communication with the GUI

# --- Configuration for CustomTkinter ---
ctk.set_appearance_mode("System")  # Modes: "System" (default), "Dark", "Light"
ctk.set_default_color_theme("blue")  # Themes: "blue" (default), "green", "dark-blue"

class PortScannerApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        # --- Window Configuration ---
        self.title("Educational Port Scanner")
        self.geometry("800x700") # Adjusted size for more content

        # --- Main Frame ---
        self.main_frame = ctk.CTkFrame(self)
        self.main_frame.pack(pady=20, padx=20, fill="both", expand=True)

        # --- Input Frame ---
        self.input_frame = ctk.CTkFrame(self.main_frame)
        self.input_frame.pack(pady=10, padx=10, fill="x")

        self.target_label = ctk.CTkLabel(self.input_frame, text="Target IP/Hostname:")
        self.target_label.grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.target_entry = ctk.CTkEntry(self.input_frame, placeholder_text="e.g., 192.168.1.1 or example.com", width=250)
        self.target_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        # Add a default value for easy testing
        self.target_entry.insert(0, "scanme.nmap.org") # Nmap's test site

        self.ports_label = ctk.CTkLabel(self.input_frame, text="Port Range:")
        self.ports_label.grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.ports_entry = ctk.CTkEntry(self.input_frame, placeholder_text="e.g., 1-1024 or 80,443,22", width=250)
        self.ports_entry.grid(row=1, column=1, padx=5, pady=5, sticky="ew")
        # Add a default value for easy testing
        self.ports_entry.insert(0, "21,22,80,443")

        self.scan_button = ctk.CTkButton(self.input_frame, text="Start Scan", command=self.start_scan_thread)
        self.scan_button.grid(row=0, column=2, rowspan=2, padx=10, pady=5, sticky="ns")
        
        self.clear_button = ctk.CTkButton(self.input_frame, text="Clear Results", command=self.clear_results)
        self.clear_button.grid(row=0, column=3, rowspan=2, padx=5, pady=5, sticky="ns")

        self.input_frame.columnconfigure(1, weight=1) # Make entry fields expand

        # --- TabView for Results and Educational Info ---
        self.tab_view = ctk.CTkTabview(self.main_frame, height=400) # Increased height
        self.tab_view.pack(pady=10, padx=10, fill="both", expand=True)
        self.tab_view.add("Scan Results")
        self.tab_view.add("Educational Info")
        self.tab_view.add("Common Ports")

        # --- Results Display ---
        self.results_textbox = ctk.CTkTextbox(self.tab_view.tab("Scan Results"), wrap="word", state="disabled", height=380) # Make it taller
        self.results_textbox.pack(pady=10, padx=10, fill="both", expand=True)

        # --- Status Bar ---
        self.status_label = ctk.CTkLabel(self.main_frame, text="Status: Idle", anchor="w")
        self.status_label.pack(pady=5, padx=10, fill="x")

        # --- Educational Info Tab Content ---
        self.populate_educational_info()
        self.populate_common_ports_info()

        # --- Queue for thread communication ---
        self.scan_queue = queue.Queue()

        # --- Check queue periodically ---
        self.after(100, self.process_queue)

    def populate_educational_info(self):
        edu_textbox = ctk.CTkTextbox(self.tab_view.tab("Educational Info"), wrap="word", state="normal", height=380) # Make it taller
        edu_textbox.pack(pady=10, padx=10, fill="both", expand=True)

        info_text = """
        **What is Port Scanning?**
        Port scanning is a process used to identify open "doors" (ports) on a computer or network host. Each port is associated with a specific service or application. For example, web servers typically use port 80 for HTTP and port 443 for HTTPS.

        **Why is it used in Ethical Hacking?**
        - **Reconnaissance:** To understand what services are running on a target system. This is a crucial first step in assessing potential vulnerabilities.
        - **Vulnerability Assessment:** Knowing which ports are open and what services are listening on them helps identify outdated or misconfigured software that could be exploited.
        - **Network Mapping:** To discover active hosts and the services they offer within a network.

        **Understanding Scan Results:**
        - **Open:** The port is actively accepting connections. A service is likely listening.
        - **Closed:** The port is accessible (it responds to probes), but there is no application listening on it.
        - **Filtered:** A firewall, filter, or other network issue is preventing the scanner from determining if the port is open or closed. The scanner usually doesn't receive a response. * (This basic scanner primarily distinguishes open/closed based on successful connection). *

        **Ethical Considerations:**
        ALWAYS ensure you have explicit permission from the system owner before scanning any host or network that you do not own. Unauthorized port scanning can be illegal and is considered a hostile act. This tool is for educational purposes and for use on systems you are authorized to test.
        """
        edu_textbox.insert("1.0", info_text)
        edu_textbox.configure(state="disabled") # Make it read-only

    def populate_common_ports_info(self):
        common_ports_textbox = ctk.CTkTextbox(self.tab_view.tab("Common Ports"), wrap="word", state="normal", height=380) # Make it taller
        common_ports_textbox.pack(pady=10, padx=10, fill="both", expand=True)
        
        common_ports_text = """
        **Commonly Encountered Ports & Services:**

        - **20 (TCP):** File Transfer Protocol (FTP) Data Transfer
        - **21 (TCP):** File Transfer Protocol (FTP) Command Control
        - **22 (TCP):** Secure Shell (SSH) - Secure remote login
        - **23 (TCP):** Telnet - Unencrypted remote login (insecure, avoid)
        - **25 (TCP):** Simple Mail Transfer Protocol (SMTP) - Email routing
        - **53 (TCP/UDP):** Domain Name System (DNS) - Resolves hostnames to IP addresses
        - **67/68 (UDP):** Dynamic Host Configuration Protocol (DHCP) - Assigns IP addresses
        - **80 (TCP):** HyperText Transfer Protocol (HTTP) - World Wide Web
        - **110 (TCP):** Post Office Protocol v3 (POP3) - Email retrieval
        - **123 (UDP):** Network Time Protocol (NTP) - Time synchronization
        - **137-139 (TCP/UDP):** NetBIOS - Network Basic Input/Output System (Windows file/printer sharing)
        - **143 (TCP):** Internet Message Access Protocol (IMAP) - Email retrieval
        - **161/162 (UDP):** Simple Network Management Protocol (SNMP) - Network device management
        - **389 (TCP/UDP):** Lightweight Directory Access Protocol (LDAP) - Directory services
        - **443 (TCP):** HyperText Transfer Protocol Secure (HTTPS) - Secure World Wide Web
        - **445 (TCP):** Microsoft-DS (SMB) - Windows file sharing, Active Directory
        - **514 (UDP):** Syslog - Log management
        - **636 (TCP/UDP):** LDAP over SSL/TLS (LDAPS)
        - **993 (TCP):** IMAP over SSL/TLS (IMAPS)
        - **995 (TCP):** POP3 over SSL/TLS (POP3S)
        - **1080 (TCP):** SOCKS Proxy
        - **1433 (TCP):** Microsoft SQL Server
        - **1521 (TCP):** Oracle Database
        - **3306 (TCP):** MySQL Database
        - **3389 (TCP):** Remote Desktop Protocol (RDP)
        - **5432 (TCP):** PostgreSQL Database
        - **5900 (TCP):** Virtual Network Computing (VNC) - Remote desktop
        - **8080 (TCP):** HTTP Alternate (often used for web proxies or development servers)
        - **8443 (TCP):** HTTPS Alternate
        """
        common_ports_textbox.insert("1.0", common_ports_text)
        common_ports_textbox.configure(state="disabled") # Make it read-only

    def add_to_results(self, message):
        self.results_textbox.configure(state="normal") # Enable writing
        self.results_textbox.insert("end", message + "\n")
        self.results_textbox.configure(state="disabled") # Disable writing
        self.results_textbox.see("end") # Scroll to the end

    def set_status(self, message):
        self.status_label.configure(text=f"Status: {message}")

    def clear_results(self):
        self.results_textbox.configure(state="normal")
        self.results_textbox.delete("1.0", "end")
        self.results_textbox.configure(state="disabled")
        self.set_status("Idle. Results cleared.")

    def start_scan_thread(self):
        target = self.target_entry.get()
        ports_str = self.ports_entry.get()

        if not target:
            self.set_status("Error: Target IP/Hostname cannot be empty.")
            self.add_to_results("[-] Error: Target IP/Hostname cannot be empty.")
            return
        if not ports_str:
            self.set_status("Error: Port range cannot be empty.")
            self.add_to_results("[-] Error: Port range cannot be empty.")
            return

        self.clear_results() # Clear previous results before starting a new scan
        self.set_status(f"Initializing scan for {target}...")
        self.scan_button.configure(state="disabled") # Disable button during scan

        # Create and start the scanning thread
        thread = threading.Thread(target=self.run_scan, args=(target, ports_str), daemon=True)
        thread.start()

    def run_scan(self, target_ip_str, ports_str):
        try:
            target_ip = socket.gethostbyname(target_ip_str) # Resolve hostname to IP
            self.scan_queue.put(f"[+] Scanning Target: {target_ip_str} ({target_ip})")
        except socket.gaierror:
            self.scan_queue.put(f"[-] Error: Invalid or unresolvable target IP/Hostname: {target_ip_str}")
            self.scan_queue.put("SCAN_DONE") # Signal completion even on error
            return

        ports_to_scan = []
        try:
            if "-" in ports_str:
                start_port, end_port = map(int, ports_str.split('-'))
                if not (0 < start_port <= 65535 and 0 < end_port <= 65535 and start_port <= end_port):
                    raise ValueError("Invalid port range.")
                ports_to_scan = range(start_port, end_port + 1)
            else:
                raw_ports = [p.strip() for p in ports_str.split(',')]
                for p_str in raw_ports:
                    if not p_str: continue # Skip empty strings if user types "80, ,22"
                    port = int(p_str)
                    if not (0 < port <= 65535):
                        raise ValueError("Invalid port number.")
                    ports_to_scan.append(port)
            if not ports_to_scan:
                 raise ValueError("No valid ports to scan.")
        except ValueError as e:
            self.scan_queue.put(f"[-] Error: Invalid port specification: {ports_str}. {e}")
            self.scan_queue.put("SCAN_DONE") # Signal completion
            return

        start_time = datetime.now()
        self.scan_queue.put(f"[+] Scan started at: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        self.scan_queue.put("-" * 50)

        open_ports_count = 0
        for port in ports_to_scan:
            self.scan_queue.put(f"Scanning port {port}...") # Update status for each port
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                socket.setdefaulttimeout(0.5) # Timeout for connection attempt
                result = sock.connect_ex((target_ip, port))
                if result == 0:
                    self.scan_queue.put(f"[+] Port {port}: Open")
                    open_ports_count +=1
                # else: # Optionally report closed ports, can be very verbose
                #     self.scan_queue.put(f"Port {port}: Closed or Filtered")
                sock.close()
            except socket.error as e: # Catch socket specific errors like host down
                self.scan_queue.put(f"Error scanning port {port}: {e}")
                # Decide if you want to stop or continue. Here we continue.
            except Exception as e: # Catch any other unexpected error during port scan
                 self.scan_queue.put(f"Unexpected error on port {port}: {e}")


        end_time = datetime.now()
        total_duration = end_time - start_time
        self.scan_queue.put("-" * 50)
        self.scan_queue.put(f"[+] Found {open_ports_count} open port(s).")
        self.scan_queue.put(f"[+] Scan finished at: {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
        self.scan_queue.put(f"[+] Total scan duration: {total_duration}")
        self.scan_queue.put("SCAN_DONE") # Signal completion

    def process_queue(self):
        try:
            while True: # Process all messages currently in the queue
                message = self.scan_queue.get_nowait() # Get message without blocking
                if message == "SCAN_DONE":
                    self.set_status("Scan complete!")
                    self.scan_button.configure(state="normal") # Re-enable button
                elif "Scanning port" in message: # For status updates
                    self.set_status(message)
                else: # For results textbox
                    self.add_to_results(message)
        except queue.Empty: # If queue is empty, do nothing
            pass
        finally:
            # Schedule this method to be called again after 100ms
            self.after(100, self.process_queue)

if __name__ == "__main__":
    app = PortScannerApp()
    app.mainloop()
