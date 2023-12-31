"""
# Pathlookup analysis
Script to display one path in IP Fabric for a given source, destination.
The output will highlight the security matching
Option to use a pivot IP is possible.
"""
import ipaddress
import json
import os
import sys
from enum import Enum

import typer
from dotenv import find_dotenv, load_dotenv
from rich import print
from rich.table import Table

from modules.pathLookup import (display_all_edges, display_path,
                                display_summary_global, display_summary_topics,
                                follow_path_first_option, get_json_pathlookup,
                                get_zonefw_interfaces)


IPF_ENV_PREFIX = "_DEMO"  # _TS / _DEMO / default to env. variables
# TS:"73eb6288-0330-4778-a053-1e332b408235" / DEMO: "12dd8c61-129c-431a-b98b-4c9211571f89"
# Azure day1: "d323b197-35bb-41e5-9a42-d4de9b38ccaa"
IPF_SNAPSHOT_OVERWRITE = "d323b197-35bb-41e5-9a42-d4de9b38ccaa"
IPF_VERIFY_OVERWRITE = False
IPF_TIMEOUT_OVERWRITE = 15

class ProtocolChoices(str, Enum):
    """
    Enum class representing protocol choices.

    Possible values:
    - tcp: TCP protocol
    - udp: UDP protocol
    - icmp: ICMP protocol
    """
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


def validate_ipv4_address_or_empty(address: str):
    """
    Validate that a string is a valid IPv4 address or subnet.

    Parameters:
    address (str): The string to validate.

    Returns:
    str: The validated IPv4 address or subnet.

    Raises:
    BadParameter: If the string is not a valid IPv4 address or subnet.
    """
    if not address:
        return None
    try:
        if ipaddress.IPv4Network(address):
            return address
    except Exception as error:
        raise typer.BadParameter(error) from error


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
    except Exception as error:
        raise typer.BadParameter(error) from error


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
        "--secure_path",
        "-sec",
        help="Secure the path: stop the flow when hiting security rules",
    ),
    l2_exclusion: bool = typer.Option(
        False,
        "--l2_exclusion",
        "-l2",
        help="Remove L2 from the displayed path",
    ),
    pivot: str = typer.Option(
        None,
        "--pivot",
        "-pivot",
        help="Enter Pivot IPv4 address",
        callback=validate_ipv4_address_or_empty,
    ),
    table_display: bool = typer.Option(
        False, "--table", "-t", help="Display result in a table format"
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
    l2_exclusion (bool): Remove L2 and FabricPath information.
    pivot (str): to use to perform two PathLookup, first to identify where the source is connected
    table (bool): display the output as a table
    file (FileText): The JSON file containing Pathlookup output (optional).

    Returns:
    None
    """
    # Load environment variables
    load_dotenv(find_dotenv(), override=True)
    # if we use ICMP, we don't need tcp/udp ports
    if protocol == "icmp":
        src_port = 0
        dst_port = 0
    secured_path_msg = (
        "Security: Stop" if secured_path else "Security: Continue"
    )
    summary_path_msg = f"[bold]Pathlookup Analysis[/bold]\n[red]{src_ip}[/red]"
    summary_path_msg += f":[blue]{src_port}[/blue]" if src_port != 0 else ""
    summary_path_msg += f" --> [red]{dst_ip}[/red]"
    summary_path_msg += f":[blue]{dst_port}[/blue]" if dst_port != 0 else ""
    summary_path_msg += f" | {protocol} | {secured_path_msg}"
    print(summary_path_msg)
    if verbose:
        print(f"[italic]Debug: ttl:{ttl}, fragment offset:{fragment_offset}\n")
    if pivot:
        summary_path_msg += f" | Pivot: `{pivot}`"
        print(
            f"Using pivot IP `{pivot}` to find where the source IP `{src_ip}` is connected\n"
        )

    if not file:
        base_url = os.getenv("".join(["IPF_URL", IPF_ENV_PREFIX]))
        auth = os.getenv("".join(["IPF_TOKEN", IPF_ENV_PREFIX]))
        snapshot_id = os.getenv("IPF_SNAPSHOT_ID", IPF_SNAPSHOT_OVERWRITE)
        ipf_verify = os.getenv("IPF_VERIFY", IPF_VERIFY_OVERWRITE)
        ipf_timeout = os.getenv("IPF_VERIFY", IPF_TIMEOUT_OVERWRITE)
        pathlookup_json = get_json_pathlookup(
            base_url=base_url,
            auth=auth,
            snapshot_id=snapshot_id,
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=protocol,
            src_port=src_port,
            dst_port=dst_port,
            ttl=ttl,
            fragment_offset=fragment_offset,
            secured_path=secured_path,
            pivot=pivot,
            ipf_verify=ipf_verify,
            ipf_timeout=ipf_timeout,
        )
        zonefw_interfaces = get_zonefw_interfaces(
            base_url, auth, snapshot_id, ipf_verify, ipf_timeout
        )
    else:
        # Using json file to generate the output
        pathlookup_json = json.load(file)
        zonefw_interfaces = None

    pathlookup_edges = pathlookup_json["graphResult"]["graphData"]["edges"]
    pathlookup_result = pathlookup_json["pathlookup"]
    pathlookup_decisions = pathlookup_json["pathlookup"]["decisions"]

    # Summary
    print("\n[bold] 1. Event Summary[/bold]")
    # Go through the topics and extract the information
    display_summary_topics(pathlookup_result)
    display_summary_global(pathlookup_result)

    if not pathlookup_edges.values() and not pivot:
        print("\n EXIT -> no Path available")
        sys.exit(0)

    # print("\n[bold] x. Path Edges[/bold] (explore all nextEdgeId)")
    # path_all_edges = display_all_edges(pathlookup_edges)

    # print("\n[bold] 2.1 Generate one Path[/bold] (follow one path Only)")
    path_first_option = follow_path_first_option(pathlookup_edges)
    
    print("\n[bold] 2. Display Decisions (one path)[/bold]")
    output_table = Table(title=summary_path_msg) if table_display else None
    if path_first_option:
        display_path(
            path=path_first_option,
            details=True,
            pathlookup_decisions=pathlookup_decisions,
            zonefw_interfaces=zonefw_interfaces,
            l2_exclusion=l2_exclusion,
            output_table=output_table,
        )
    else:
        print("No Path to display")


if __name__ == "__main__":
    app()
