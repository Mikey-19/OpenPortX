OpenPortX - Port Scanner Tool (GUI)

 
 Introduction
 
OpenPortX is a modern and intuitive port scanner built with Python and PyQt5. It is designed for cybersecurity students, penetration testers, and IT professionals who need a fast, efficient, and user-friendly tool to scan open ports on a target system.

 Features
 
• Scan a host's ports within a custom range

• Detect services running on open ports

• Banner grabbing for additional service information

• Adjustable thread count for faster scans

• Modern GUI with Dark/Light theme support

• Progress bar to track scanning process

• Export results to CSV for reporting



 Installation
 
1. Clone the repository:
   ```bash
   git clone https://github.com/Mikey-19/OpenPortX
   ```
   
4. Navigate into the folder:
   
   ```bash
   cd OpenPortX
   ```
   
7. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ``` 
 Usage
 
Run the tool using the command:
```bash
python port_scanner_gui.py
```
   
   
 GUI Overview
 
The OpenPortX interface allows you to:

• Enter a target host (domain or IP address)

• Specify start and end port range

• Set maximum worker threads for scanning

• View results in a scrollable table (Port, Service, Status, Banner)

• Export results to a CSV file


 Screenshots
 
Below are placeholder sections for screenshots of the tool in action. You can replace them with actual images after running the tool.

• Results
![Port Scan Result](Port-Scanner/port_scan_results%20in%20Excel.png)
• Scan Results in Dark Mode
![Port Scan dark](Port-Scanner/Port-Scanner%dark.png)

• Scan Results in Light Mode
![Port Scan light](Port-Scanner/Port-Scanner%light.png)
 License
 
This project is licensed under the MIT License – you are free to use, modify, and distribute it.

