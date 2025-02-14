# Sirius Scan Engine

SiriusScan is a modular, extensible vulnerability scanner built on top of industry tools like Nmap and RustScan. It leverages design patterns such as Strategy, Factory, and Command to separate concerns and improve maintainability. The scanner listens for incoming scan requests via RabbitMQ, processes them through multiple scanning phases (discovery and vulnerability), and updates scan state in a key–value store (KVStore) for live monitoring.

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture & Design Patterns](#architecture--design-patterns)
- [Directory Structure](#directory-structure)
- [Getting Started](#getting-started)
- [Usage](#usage)
- [Testing](#testing)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

SiriusScan is designed to streamline the process of network vulnerability scanning by:
- **Decoupling responsibilities**: Separating scan management, strategy implementations, and KV store updates.
- **Leveraging message queues**: Using RabbitMQ to receive and process scan commands.
- **Real-time updates**: Keeping scan results updated in a KV store for live monitoring.
- **Extensibility**: Easily adding new scanning strategies or tools by updating the factory and strategy implementations.

---

## Features

- **Discovery Phase**: Uses RustScan to quickly identify live hosts.
- **Vulnerability Phase**: Uses Nmap to scan for vulnerabilities and enriches results with NVD data.
- **Live Updates**: Integrates with a KV store to update scan progress in real time.
- **Modular Architecture**: Employs Strategy and Factory patterns for scalable design.
- **Asynchronous Processing**: Leverages Go's goroutines for concurrent target processing.

---

## Architecture & Design Patterns

- **Strategy Pattern**: Encapsulates scanning techniques (e.g., discovery and vulnerability scanning) in interchangeable implementations.
- **Factory Pattern**: Dynamically creates the appropriate scan strategy based on the scan phase.
- **Command Pattern**: (Potential extension) Can encapsulate scanning actions for scheduling, logging, or retries.
- **Observer Pattern**: (In future iterations) Could be used for real-time notifications to update UI components.

---

## Directory Structure

```plaintext
.
├── cmd
│   └── scanner
│       └── main.go          # Application entry point
└── internal
    └── scan
        ├── factory.go       # Factory to create scan strategies
        ├── helpers.go       # Helper functions (e.g., calculateSeverity)
        ├── manager.go       # ScanManager: listens for and processes scan requests
        ├── strategies.go    # ScanStrategy interface and its implementations
        └── updater.go       # ScanUpdater: handles KV store scan state updates
└── modules
    └── nmap
        ├── nmap.go          # Nmap integration library
    └── rustscan
        ├── rustscan.go      # Rustscan integration library 
└── tests
    └── test.go              # Individual function tests and development execution testing.
```        
        
## Getting Started

### Prerequisites

- **Go 1.XX+**: Make sure you have Go installed on your system.
- **RabbitMQ**: Used for messaging. Ensure it's running and accessible.
- **KV Store**: A key–value store implementation provided by the `go-api/sirius/store` package.
- **Other Dependencies**: Refer to the `go.mod` file for the complete list of Go modules.

### Installation

1. **Clone the repository:**

   ```bash
   git clone https://github.com/yourusername/sirius-scan.git
   cd sirius-scan
   ```
   
2.	Install dependencies:

    ```bash
    go mod tidy
    ```

go build -o scanner ./cmd/scanner
./scanner


3.	Send a scan request:
Send a JSON message to the scan queue, e.g.:

```json
{
  "message": "192.168.1.1,192.168.1.2"
}
```

## Testing
	•	Unit Tests: Write unit tests for individual components (e.g., strategies, updater, manager). Place tests in corresponding _test.go files within the internal/scan package.
	•	Integration Tests: Consider setting up integration tests to simulate scan requests and verify KV store updates.

## Contributing

Contributions are welcome! Please follow these guidelines:
	1.	Fork the repository and create your feature branch.
	2.	Write tests for your changes.
	3.	Ensure code style consistency and run go fmt before submitting.
	4.	Submit a pull request with a detailed description of your changes.

For major changes, please open an issue first to discuss what you would like to change.

## License

This project is licensed under the MIT License. See the LICENSE file for details.