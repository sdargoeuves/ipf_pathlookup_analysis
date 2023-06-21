import ipaddress
import json
import sys
from enum import Enum

import typer
from modules.pathLookup import (
    get_json_pathlookup,
    display_summary_topics,
    display_summary_global,
    display_all_edges,
    follow_path_first_option,
)
from rich import print


class ProtocolChoices(str, Enum):
    tcp = "tcp"
    udp = "udp"
    icmp = "icmp"


app = typer.Typer(add_completion=False)


def validate_option_tcp_udp_callback(
    ctx: typer.Context, option: typer.Option, value: str
):
    """
    Callback function to validate that the option is only used with TCP or UDP protocols.

    Parameters:
    ctx (Context): The Typer context object.
    option (Option): The Typer option object.
    value (str): The value of the option.

    Returns:
    str: The validated value of the option.
    """
    if ctx.params["protocol"] not in ["tcp", "udp"]:
        print(f"ICMP protocol is selected, `{option.name}` will not be used")
    return value


def validate_range_callback(value: int, min_value: int, max_value: int):
    """
    Validate that a value is within a given range.

    Parameters:
    value (int): The value to validate.
    min_value (int): The minimum allowed value.
    max_value (int): The maximum allowed value.

    Returns:
    int: The validated value.

    Raises:
    BadParameter: If the value is not within the given range.
    """
    if value < min_value or value > max_value:
        raise typer.BadParameter(f"Value must be between {min_value} and {max_value}")
    return value


def validate_ipv4_address(address: str):
    """
    Validate that a string is a valid IPv4 address or subnet.

    Parameters:
    address (str): The string to validate.

    Returns:
    str: The validated IPv4 address or subnet.

    Raises:
    BadParameter: If the string is not a valid IPv4 address or subnet.
    """
    try:
        if ipaddress.IPv4Network(address):
            return address
    except Exception as e:
        raise typer.BadParameter(e) from e


@app.command()
def main(
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose mode."),
    src_ip: str = typer.Option(
        "",
        "--source_ip",
        "-s",
        help="Enter Source IPv4 address or subnet",
        callback=validate_ipv4_address,
    ),
    dst_ip: str = typer.Option(
        "",
        "--destination_ip",
        "-d",
        help="Enter Destination IPv4 address or subnet",
        callback=validate_ipv4_address,
    ),
    protocol: ProtocolChoices = typer.Option(
        "icmp",
        "--protocol",
        "-p",
        help="Enter Protocol (tcp, udp, icmp)",
        case_sensitive=False,
    ),
    dst_port: str = typer.Option(
        "443",
        "--destination_port",
        "-dp",
        help="Enter Destination Ports (udp, tcp)",
        callback=validate_option_tcp_udp_callback,
    ),
    src_port: str = typer.Option(
        "1024",
        "--source_port",
        "-sp",
        help="Enter Source Ports (udp, tcp)",
        callback=validate_option_tcp_udp_callback,
    ),
    ttl: int = typer.Option(
        128,
        "--ttl",
        "-ttl",
        help="Enter Time To Live (TTL)",
        callback=lambda value: validate_range_callback(value, 0, 255),
    ),
    fragment_offset: int = typer.Option(
        0,
        "--fragment_offset",
        "-fo",
        help="Enter Fragment Offset",
        callback=lambda value: validate_range_callback(value, 0, 8191),
    ),
    secured_path: bool = typer.Option(
        False,
        "--security_",
        "-sec",
        help="Secure the path: stop the flow when hiting security rules",
    ),
    file: typer.FileText = typer.Option(
        None,
        "--file",
        "-f",
        help="JSON file containing Pathlookup output",
    ),
):
    """
    Analyze a path using Pathlookup and display the results.

    Parameters:
    verbose (bool): Whether to enable verbose mode or not.
    src_ip (str): The source IP address or subnet.
    dst_ip (str): The destination IP address or subnet.
    protocol (ProtocolChoices): The IP protocol to use (e.g. "tcp", "udp", "icmp").
    dst_port (str): The destination port number (only used with TCP/UDP protocols).
    src_port (str): The source port number (only used with TCP/UDP protocols).
    ttl (int): The time-to-live (TTL) value.
    fragment_offset (int): The fragment offset value.
    secured_path (bool): Whether to use a secured path or not.
    file (FileText): The JSON file containing Pathlookup output (optional).

    Returns:
    None
    """
    # if we use ICMP, we don't need tcp/udp ports
    if protocol == "icmp":
        src_port = 0
        dst_port = 0
    secured_path_msg = (
        "Security Rules: Stop" if secured_path else "Security Rules: Continue"
    )
    print(
        f"\n--- [reverse]Pathlookup Analysis[/reverse] ---\n\
Source: [red]{src_ip}[/red]:[blue]{src_port}[/blue] | \
Destination: [red]{dst_ip}[/red]:[blue]{dst_port}[/blue] | {protocol} | {secured_path_msg}"
    )
    if verbose:
        print(f"[italic]Debug: ttl:{ttl}, fragment offset:{fragment_offset}")

    if not file:
        pathlookup_json = get_json_pathlookup(
            src_ip,
            dst_ip,
            protocol,
            src_port,
            dst_port,
            ttl,
            fragment_offset,
            secured_path,
        )
    else:
        # Using json file to generate the output
        pathlookup_json = json.load(file)

    pathlookup_edges = pathlookup_json["graphResult"]["graphData"]["edges"]
    pathlookup_result = pathlookup_json["pathlookup"]

    # Summary
    print("\n[bold] 1. Event Summary[/bold]")
    # Go through the topics and extract the information
    display_summary_topics(pathlookup_result)
    display_summary_global(pathlookup_result)

    if not pathlookup_edges.values():
        print("\n EXIT -> no Path available")
        sys.exit(0)

    print("\n[bold] 2. Path Edges[/bold] (explore all nextEdgeId)")
    display_all_edges(pathlookup_edges)

    print("\n[bold] 3. Path Edges[/bold] (follow one path Only)")
    path_first_option = follow_path_first_option(pathlookup_edges)

    print("\n[bold] 4. Path Decisions[/bold]")
    # get extra information and add it to the result

if __name__ == "__main__":
    app()
