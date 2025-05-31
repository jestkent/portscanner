# Educational GUI Port Scanner

## ⚠️ Ethical Hacking Disclaimer
This tool is intended for educational purposes and for use on systems and networks for which you have **explicit, authorized permission** to scan. Unauthorized port scanning can be illegal and is considered a hostile act. Always respect privacy and legal boundaries. The developers of this tool are not responsible for its misuse.

## 📖 Overview
The Educational GUI Port Scanner is a user-friendly Python application designed to help users understand the basics of network port scanning. It provides a graphical interface to scan for open ports on a target IP address or hostname, along with educational information about port scanning concepts and common network services.

## ✨ Features
* **Modern GUI:** Built with CustomTkinter for a clean and modern look and feel.
* **Target Specification:** Scan either an IP address (e.g., `192.168.1.1`) or a hostname (e.g., `example.com`).
* **Flexible Port Selection:**
    * Scan a range of ports (e.g., `1-1024`).
    * Scan specific, comma-separated ports (e.g., `22,80,443`).
* **Non-Blocking Scans:** The scanning process runs in a separate thread, keeping the GUI responsive.
* **Real-time Results:** View open ports as they are discovered in the "Scan Results" tab.
* **Status Updates:** A status bar provides feedback on the current operation (e.g., "Scanning port 80...", "Scan complete!").
* **Educational Tabs:**
    * **Educational Info:** Explains what port scanning is, its relevance in ethical hacking, how to interpret results, and critical ethical guidelines.
    * **Common Ports:** A quick reference list of common TCP/UDP ports and their associated services.
* **Clear Results:** Easily clear previous scan results.
* **Cross-Platform (Potentially):** Python and CustomTkinter are generally cross-platform, though testing on all OS is recommended.

## 🛠️ Requirements
* Python 3.x
* CustomTkinter library

## 🚀 Installation

1.  **Clone or Download the Code:**
    If this were a Git repository, you would clone it. For now, ensure you have the `gui_port_scanner.py` (or equivalent) file.

2.  **Install Python:**
    If you don't have Python installed, download it from [python.org](https://www.python.org/downloads/) and install it. Make sure to add Python to your system's PATH during installation.

3.  **Install CustomTkinter:**
    Open your terminal or command prompt and run the following command:
    ```bash
    pip install customtkinter
    ```
    If you have multiple Python versions, you might need to use `pip3` instead of `pip`.

## 🏃 How to Run

1.  **Navigate to the Directory:**
    Open your terminal or command prompt and navigate to the directory where you saved the `gui_port_scanner.py` file.
    ```bash
    cd path/to/your/scanner_directory
    ```

2.  **Run the Script:**
    Execute the Python script:
    ```bash
    python gui_port_scanner.py
    ```
    Or, if you use `python3`:
    ```bash
    python3 gui_port_scanner.py
    ```

## 🖥️ How to Use

1.  **Launch the Application:** Run the script as described above. The GUI window will appear.

2.  **Enter Target:**
    * In the "Target IP/Hostname" field, enter the IP address or hostname you wish to scan (e.g., `scanme.nmap.org` - **this is a safe target provided by Nmap for testing scanners**).

3.  **Specify Ports:**
    * In the "Port Range" field:
        * For a range: `1-100`
        * For specific ports: `21,22,80,443`
        * The application defaults to `21,22,80,443`.

4.  **Start Scan:**
    * Click the "Start Scan" button.
    * The button will disable during the scan, and the status bar will show progress.

5.  **View Results:**
    * Open ports will be listed in the "Scan Results" tab.
    * The status bar will indicate when the scan is complete.

6.  **Explore Educational Tabs:**
    * Click on the "Educational Info" tab to learn more about port scanning.
    * Click on the "Common Ports" tab for a reference of common services.

7.  **Clear Results:**
    * Click the "Clear Results" button to clear the output in the "Scan Results" tab.

## 📝 Notes
* **Timeout:** The scanner uses a short timeout (0.5 seconds by default) for each port connection attempt. Ports that don't respond within this time are considered closed or filtered.
* **Hostname Resolution:** If you provide a hostname, the scanner will first attempt to resolve it to an IP address.
* **Error Handling:** Basic error handling is in place for invalid inputs or unresolvable hostnames.

## 🤝 Contributing (Example - if this were a larger project)
Contributions are welcome! If you'd like to contribute:
1.  Fork the repository.
2.  Create a new branch (`git checkout -b feature/YourFeature`).
3.  Make your changes.
4.  Commit your changes (`git commit -m 'Add some feature'`).
5.  Push to the branch (`git push origin feature/YourFeature`).
6.  Open a Pull Request.

## 📜 License
This project is for educational purposes. Please ensure responsible and ethical use. (If you were to add a specific open-source license, you'd mention it here, e.g., MIT License).
