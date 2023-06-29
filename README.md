# Pathlookup Analysis Tool

This repository contains a Python script for analyzing paths using Pathlookup and displaying the results.

## Introduction

The Pathlookup Analysis Tool is used to analyze network paths between a source and destination IP address. It utilizes the Pathlookup service to retrieve and display the path information.

## Prerequisites

- Python 3.8 or above is required to run this script. Please make sure you have the appropriate version of Python installed on your system.

## Dependencies

The following dependencies are required to run the script, including a python version 3.8+

- `ipaddress`
- `json`
- `os`
- `sys`
- `enum`
- `dotenv`
- `typer`
- `rich`

Please make sure to install these dependencies before running the script.

## Installation

To install the required dependencies, run the following command:

```shell
pip install ipaddress json5 os_sys enum34 python_dotenv typer rich
```

## Usage

The script accepts several command-line arguments to customize the analysis. Here are the available options:

- --verbose or -v: Enable verbose mode.
- --source_ip or -s: Enter the source IPv4 address or subnet.
- --destination_ip or-d: Enter the destination IPv4 address or subnet.
- --protocol or -p: Enter the protocol (tcp, udp, icmp).
- --destination_port or -dp: Enter the destination ports (udp, tcp).
- --source_port or -sp: Enter the source ports (udp, tcp).
- --ttl or -ttl: Enter the Time To Live (TTL).
- --fragment_offset or -fo: Enter the Fragment Offset.
- --security_ or -sec: Secure the path: stop the flow when hitting security rules.
- --l2_exclusion or -l2: Remove L2 from the displayed path.
- --pivot or -pivot: Enter the Pivot IPv4 address.
- --file or -f: JSON file containing Pathlookup output.

To run the script, use the following command:

```shell
python your_script.py --source_ip 192.168.1.10 --destination_ip 8.8.8.8 --protocol icmp
```

Replace the IP addresses and protocol with your desired values.

## Output

The script will display the analysis results, including the path information, event summary, and decisions made.
Additional Information

- The --verbose option can be used to enable verbose mode and get more detailed output.
- When using the ICMP protocol, the --destination_port and --source_port options will not be used.
- The --security_ option can be used to secure the path and stop the flow when hitting security rules.
- The --l2_exclusion option can be used to remove Layer 2 information from the displayed path.
- The --pivot option is used to find where the source IP is connected using a pivot IP.

Feel free to explore different options and customize the analysis based on your needs.
