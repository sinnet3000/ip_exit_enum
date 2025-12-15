# IP Exit Enumerator

## Overview

IP Exit Enumerator is a command-line tool designed to discover and report the public IP addresses (both IPv4 and IPv6) that your machine uses to connect to the internet. It simultaneously queries a collection of external HTTP and STUN services to quickly identify your potential exit IPs.

This provides a more reliable result than relying on a single service, which might be unavailable or provide inconsistent information.

The project was initially conceived while on a hotel network experiencing flaky load balancing rules. This tool was developed to better probe and understand how such networks handled external IP egress.

## Project History

This project originally started as a small utility written in Python. As the scope grew to include more concurrent service checks and a desire for a single, dependency-free binary, the decision was made to rewrite it in Go. The modern Go version offers superior performance for this network-bound task.

The original Python implementation is preserved for historical purposes in the `legacy/` directory.

## Features

- **Concurrent Queries**: Checks multiple services at once for fast results.
- **Multiple Protocols**: Uses both HTTP-based IP echo services and STUN (Session Traversal Utilities for NAT) servers.
- **IPv4 & IPv6 Support**: Discovers public addresses for both major IP versions.
- **Verbose Mode**: An optional `-v` flag provides detailed logs of which services were contacted and their responses.

## Prerequisites

- **Go**: Version 1.22.5 or newer.

## Installation & Usage

1.  **Clone the repository:**
    ```sh
    git clone <repository-url>
    cd ip_exit_enum
    ```

2.  **Build the binary:**
    ```sh
    go build .
    ```

3.  **Run the enumerator:**
    ```sh
    ./ip_exit_enum
    ```

4.  **Run in Verbose Mode:**
    To see detailed information about each service check, use the `-v` flag.
    ```sh
    ./ip_exit_enum -v
    ```

## Legacy Version

The original Python script can be found in the `legacy/` directory. To run it, you will need Python 3 and the packages listed in `legacy/requirements.txt`.

```sh
cd legacy
pip install -r requirements.txt
python ip_exit_enum.py
```

## License

This project is licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).

Copyright (C) 2025 Luis Colunga (@sinnet3000). All rights reserved.

See the [LICENSE](LICENSE) file for full details.