# CodeAlpha_PacketSniffer

# Packet Sniffer in Python

## Overview
This is a Python-based packet sniffer that captures and analyzes network packets. It provides functionalities such as real-time packet capturing, protocol decoding, and output logging.

## Features
- Captures packets in real time
- Supports multiple network protocols (requires `netprotocols` module)
- Outputs packet details to the console
- Provides filtering options (future enhancement)
- Saves captured packets to a file (planned feature)

## Requirements
- Python 3.x
- `socket` module (built-in)
- `struct` module (built-in)
- `netprotocols` module (currently missing, needs implementation)

## Installation
1. Clone this repository:
   ```bash
   git clone https://github.com/yourusername/packet-sniffer.git
   cd packet-sniffer
   ```
2. Ensure you have Python installed:
   ```bash
   python3 --version
   ```
3. Install dependencies (if required in the future):
   ```bash
   pip install -r requirements.txt
   ```

## Usage
Run the packet sniffer with:
```bash
python3 sniffer.py
```

## Project Structure
```
packet-sniffer/
│-- core.py        # Core logic for packet capturing
│-- output.py      # Handles formatting and displaying packet data
│-- sniffer.py     # Main entry point for the sniffer
│-- README.md      # Project documentation
```

## Future Improvements
- Implement the `netprotocols` module for enhanced packet decoding.
- Add filtering options to capture specific protocols.
- Optimize performance for high-speed network traffic.
- Save packet logs to a file for later analysis.

## Contributing
Contributions are welcome! Feel free to fork the repository and submit a pull request.


