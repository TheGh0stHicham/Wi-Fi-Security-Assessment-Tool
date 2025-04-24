# Wi-Fi Security Assessment Tool

A Python GUI application for network security professionals to perform authorized Wi-Fi security assessments. This tool is designed for educational purposes and legitimate security testing.

## Features

- **Network Scanner**: Discover nearby Wi-Fi networks and identify their security properties
- **WPS Vulnerability Testing**: Test WPS-enabled networks for potential security weaknesses
- **Dictionary Testing**: Simulate password testing using customizable wordlists
- **Wordlist Management**: Create, browse, and analyze security testing wordlists
- **Detailed Logging**: Comprehensive logging of all operations for audit trails

## Disclaimer

**IMPORTANT**: This software is provided for **EDUCATIONAL PURPOSES ONLY**. It is designed for cybersecurity professionals, researchers, and system administrators to test the security of their own networks or networks they have explicit permission to test.

Unauthorized access to computer networks is illegal and unethical. The author accepts no liability for misuse of this software. Users are responsible for ensuring they comply with all applicable laws and regulations.

## Installation

### Prerequisites

- Python 3.6 or higher
- Tkinter (included in standard Python)
- Scapy (for network packet manipulation)

### Setup

1. Clone the repository:
```
git clone https://github.com/TheGh0stHicham/wifi-security-assessment-tool.git
cd wifi-security-assessment-tool
```

2. Install required dependencies:
```
pip install scapy
```

3. Run the application:
```
python wifi_security_tool.py
```

## Usage

### Network Scanning

1. Select your wireless network interface from the dropdown
2. Click "Start Scan" to discover nearby Wi-Fi networks
3. Networks will appear in the list with their properties

### Security Testing

1. Select a network from the scan results
2. For WPS-enabled networks, use the "Test WPS Vulnerability" button
3. For password-protected networks, use the "Start Dictionary Test" button
4. Results will be displayed in the test results area

### Wordlist Management

1. Navigate to the "Wordlists" tab
2. Create sample wordlists or browse existing ones
3. Analyze wordlist statistics to optimize testing

## Legitimate Use Cases

- Testing security of your own Wi-Fi networks
- Authorized penetration testing with explicit permission
- Educational demonstrations in cybersecurity courses
- Security research in controlled environments

## Technical Details

The application is built with:
- Python 3 for core functionality
- Tkinter for the graphical user interface
- Scapy for network interactions
- Threading for non-blocking operations

## Acknowledgments

- This tool was created for educational purposes to demonstrate Wi-Fi security concepts
- Inspired by legitimate security assessment tools used by professionals
