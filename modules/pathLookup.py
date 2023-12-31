"""
# pathLookup.py
Function to extract the information from the IPF's PathLookup output.
"""
import re

from ipfabric import IPFClient
from ipfabric.diagrams import Algorithm, IPFDiagram, Unicast
from rich import print
from rich.table import Table

from .pivot import return_entry_point_pivot
from .utilis import display_severity, remove_vdevice_id, replace_vdevice_id

GREEN = "0"
BLUE = "10"
AMBER = "20"
RED = "30"
COLOUR_DICT = {"Green": GREEN, "Blue": BLUE, "Amber": AMBER, "Red": RED}
STOP_TRACE = ["dropped", "accepted"]
EVENT_HEADER_TYPE = ("vxlan", "capwap", "gre", "esp", "mpls", "ip", "fp")
L2_EXCLUSION_PROTOCOL = ("l2", "fp")
CHAIN_SWITCHING = "switching-nexthop"


def get_zonefw_interfaces(
    base_url: str,
    auth: str,
    snapshot_id: str,
    ipf_verify: bool = False,
    timeout: int = 10,
):
    """
    Get from IP Fabric the tables containing the ZoneFW per Interfaces
    """
    ipf = IPFClient(
        base_url=base_url,
        auth=auth,
        snapshot_id=snapshot_id,
        verify=ipf_verify,
        timeout=timeout,
    )
    return ipf.technology.security.zone_firewall_interfaces.all()


def get_json_pathlookup(
    base_url: str,
    auth: str,
    snapshot_id: str,
    src_ip: str,
    dst_ip: str,
    protocol: str,
    src_port: str,
    dst_port: str,
    ttl: str,
    fragment_offset: str,
    secured_path: bool,
    pivot: str = None,
    ipf_verify: bool = False,
    ipf_timeout: int = 10,
    ipf_diagram: IPFDiagram = None,
    ipf_close: bool = True,
):
    """
    Call IP Fabric with the given parameters and return the resulting JSON output.

    Parameters:
    src_ip (str): The source IP address.
    dst_ip (str): The destination IP address.
    protocol (str): The IP protocol to use (e.g. "tcp", "udp").
    src_port (str): The source port number.
    dst_port (str): The destination port number.
    ttl (str): The time-to-live (TTL) value.
    fragment_offset (str): The fragment offset value.
    secured_path (bool): Whether to use a secured path or not.

    Returns:
    str: The JSON file returned by IP Fabric.
    """
    # Initialize an IPFDiagram object with the given parameters
    firstHopAlgorithm = {"type": "automatic"}
    if not ipf_diagram:
        ipf_diagram = IPFDiagram(
            base_url=base_url,
            auth=auth,
            snapshot_id=snapshot_id,
            verify=ipf_verify,
            timeout=ipf_timeout,
        )
    if pivot:
        pivot_pathlookup_result = get_json_pathlookup(
            base_url=base_url,
            auth=auth,
            snapshot_id=snapshot_id,
            ipf_diagram=ipf_diagram,
            src_ip=pivot,
            dst_ip=src_ip,
            protocol=protocol,
            src_port=src_port,
            dst_port=dst_port,
            ttl=ttl,
            fragment_offset=fragment_offset,
            secured_path=False,
            ipf_close=False,
        )
        if entry_point := return_entry_point_pivot(pivot_pathlookup_result):
            pivot_msg = f"[blue][italic][bold]Info: [/bold][/blue][/italic]Entry point for the source `{src_ip} is: `{entry_point['hostname']}@{entry_point['iface']}`"
            firstHopAlgorithm = Algorithm(entryPoints=[entry_point])
        else:
            pivot_msg = f"[yellow][italic][bold]Warning: [/bold][/yellow][/italic]Pivot `{pivot}` will not be used. From the pivot to the source `({src_ip})` there is no transit."
        print(pivot_msg)

    uni = Unicast(
        startingPoint=src_ip,
        destinationPoint=dst_ip,
        protocol=protocol,
        srcPorts=src_port,
        dstPorts=dst_port,
        ttl=ttl,
        fragmentOffset=fragment_offset,
        securedPath=secured_path,
        firstHopAlgorithm=firstHopAlgorithm,
    )

    # Call IP Fabric and retrieve the path lookup JSON file
    pathlookup_json = ipf_diagram.diagram_json(uni)

    # Close the IPFDiagram object
    if ipf_close:
        ipf_diagram.close()

    # Return the JSON file
    return pathlookup_json


def display_summary_topics(pathlookup_result: dict):
    """
    Display summary information, highlighting issues with NAT, ACL, etc.

    Parameters:
    pathlookup_result (dict): A dictionary containing the results of the path lookup operation.

    Returns:
    None
    """
    # Initialize a dictionary to store the summary information for each topic
    topics_results = {}

    # Print the Summary header
    print("[bold]  - Summary[/bold]")

    # Iterate over each topic in the eventsSummary dictionary
    for topic, topic_data in pathlookup_result["eventsSummary"]["topics"].items():
        topics_results[topic] = []

        # Iterate over each color in the COLOUR_DICT dictionary
        for colour, colour_key in COLOUR_DICT.items():
            value = topic_data.get(colour_key, 0)
            # If the color value is not zero, add it to the list of results for this topic
            if value != 0:
                topics_results[topic].append(f"      - {colour}: {value}")

    # Display the summary information for each topic
    if not any(topics_results.values()):
        print("No summary information for this path")
    else:
        for topic, topic_results in topics_results.items():
            if topic_results:
                print(f"    - {topic}")
                print("\n".join(f"{result}" for result in topic_results))


def display_summary_global(pathlookup_result: dict):
    """
    Display information related to the Global key.

    Parameters:
    pathlookup_result (dict): A dictionary containing the results of the path lookup operation.

    Returns:
    None
    """
    # Check if there is any Global information to display
    if len(pathlookup_result["eventsSummary"]["global"]) > 0:
        global_info = pathlookup_result["eventsSummary"]["global"]

        # Print the Global information header
        print("[bold]  - Global[/bold]")

        # Print each piece of Global information
        for info in global_info:
            message = [info["name"]]
            message.extend(info["details"])
            message.append(str(info["severity"]))
            message = " | ".join(message)
            print(f"{message}")


def display_all_edges(pathlookup_edges: dict):
    """
    Display all edges in the path, highlighting when multiple egress points exist.

    Parameters:
    pathlookup_edges (dict): A dictionary containing information about the edges in the path.

    Returns:
    list: A list of all edges involved in the path.
    """
    # Collect all next edge IDs in a list
    next_edge_ids = [next(iter(pathlookup_edges.values()))["id"]]
    for edge in pathlookup_edges.values():
        if len(edge["nextEdgeIds"]) > 1:
            next_edge_ids.extend(
                f"{path}--multiple-egress" for path in edge["nextEdgeIds"]
            )
        elif len(edge["nextEdgeIds"]) == 1:
            next_edge_ids.append(edge["nextEdgeIds"][0])
        # else:
        #     next_edge_ids.append("no_next_edge")

    # Process each edge ID to extract the relevant information
    processed_edges = []
    for edge in next_edge_ids:
        processed_edge = edge.split("--")
        processed_edge = [
            f"{e.split('!')[1]}"
            if "!" in e
            else f"{e.split('@')[1]}"
            if "@" in e
            else e
            for e in processed_edge
        ]
        processed_edges.append("--".join(processed_edge))

    # Print the list of edges, highlighting multiple egress points
    final_all_edges = []
    prev_device_src = ""
    for edge in processed_edges:
        if edge not in final_all_edges:
            final_all_edges.append(edge)
            device_src = edge.split("@")[0] if edge.split("@") else ""
            if device_src == prev_device_src:
                print("".join([" └ ", edge])) if "multiple-egress" in edge else print(edge)
            else:
                print(edge)
            prev_device_src = device_src

    return final_all_edges


def follow_path_first_option(pathlookup_edges: dict):
    """
    Follow a path starting from the beginning and always take the first option when there are multiple choices for the egress interface.

    Parameters:
    pathlookup_edges (dict): A dictionary containing information about the edges in the path.

    Returns:
    List of edges involved in the Path (always selecting the first option if multiple choices)
    """

    # Start from the first entry in the pathlookup_edges dictionary
    if pathlookup_edges.values():
        first_edge = next(iter(pathlookup_edges.values()))

        # Initialize the first path with the ID of the first edge
        first_path_edges = [first_edge["id"]]

        # Follow the first option for egress interfaces until there is no next edge
        next_edge_id = (
            first_edge["nextEdgeIds"][0] if len(first_edge["nextEdgeIds"]) > 0 else None
        )
        prev_next_edge_id = first_edge["id"]
        while next_edge_id is not None:
            if next_edge_id in pathlookup_edges:
                first_path_edges.append(pathlookup_edges[next_edge_id]["id"])
            else:
                # in this situation we can encounter this nextEdgeIds
                # vDevice/913624679@ge-0/0/4.200--dropped--#0
                # we need to add the hostname
                new_nextedge_id = replace_vdevice_id(pathlookup_edges[prev_next_edge_id])
                first_path_edges.append(new_nextedge_id)
            prev_next_edge_id = next_edge_id
            next_edge_id = (
                pathlookup_edges[prev_next_edge_id]["nextEdgeIds"][0]
                if prev_next_edge_id in pathlookup_edges
                and len(pathlookup_edges[prev_next_edge_id]["nextEdgeIds"]) > 0
                else None
            )

        # Build the new Display (ASCII GRAPH)
        # generate_ascii_graph(first_path_edges)
        return first_path_edges


def get_edge_details(
    pathlookup_decisions: dict,
    device_name: str,
    device_id: str,
    edge: str,
    egress: str,
    first_edge: bool = False,
    zonefw_interfaces=None,
):
    """
    Retrieves and returns the details of the given edge.
    Args:
        pathlookup_decisions (dict): Dictionary containing path decisions
        device_name (str): Source device of the edge
        device_id (str): Unique identifier of the source device
        edge (str): Edge of the path
        egress (str): Egress port of the edge
        first_edge (bool, optional): Flag to indicate if this is the first edge in the path. Defaults to False.
        zonefw_interfaces (dict, optional): Dictionary containing zone firewall interfaces. Defaults to None.

    Returns:
        str: Formatted string with the details of the edge"""

    def get_security_traces(traces, security_info=""):
        """
        Returns a string with the security event information from the traces.

        :param traces: List containing traces from pathlookup_decisions
        :param security_info: Optional preexisting string with the security event information
        :return: A formatted string with the security event information
        """
        # Loop through each trace in the traces list and extract the security event details
        for trace in traces:
            for trace_detail in trace:
                # Check if any events in the trace contain the word "security"
                for event in trace_detail["events"]:
                    security_info = get_security_event(event, security_info)
                    if security_info:
                        # Exit the loop once a match is found
                        break
                if security_info:
                    break
            if security_info:
                break

        return security_info

    def get_security_event(event, security_info=""):
        """
        Returns a formatted string with the security event information from the event dictionary.

        :param event: Dictionary containing the security event information
        :param security_info: Optional preexisting string with the security event information
        :return: A formatted string with the security event information
        """
        # Return the preexisting security info if provided
        if security_info:
            return security_info

        # If no preexisting security info provided, construct the security info string
        security_info = ""
        if "security" in event.get("type", ""):
            security_info = f"{display_severity(event['severityInfo']['severity'])} | {event['decidingPolicyName']}"
            # security_info += f"{display_severity(event['severityInfo']['severity'])}"
            if zonefw_interfaces:
                security_info += find_zonefw_interface(
                    device_name, egress, zonefw_interfaces
                )

        return security_info

    def get_protocol_traces(traces):
        """
        Returns the first matching headerType or 'n/a' if no matches are found.

        :param traces: A list of traces which contain the event dictionary.
        :return: A formatted string with the protocol event information.
        """
        list_header_type = [
            event.get("headerType", "")
            for trace in traces
            for trace_detail in trace
            for event in trace_detail["events"]
        ]
        if CHAIN_SWITCHING in [
            trace_detail["chain"] for trace in traces for trace_detail in trace
        ]:
            # Return "l2" if CHAIN_SWITCHING is found
            return "l2"
        for headerType in EVENT_HEADER_TYPE:
            if headerType in list_header_type:
                # Return the first matching headerType
                return headerType
        # Return "n/a" if no matches are found
        return "n/a"

    def find_zonefw_interface(device: str, interface: str, zonefw_interfaces):
        """
        Searches for the zoneFW for the specified interface and device.

        :param device: Name of the device
        :param interface: Name of the interface
        :param zonefw_interfaces: Dictionary containing zone firewall interfaces
        :return: A string with the zone firewall information, separated by |
        """
        for intf in zonefw_interfaces:
            if intf["hostname"] == device and intf["intName"] == interface:
                return f" | {'/'.join(intf['zone'])}"
        return ""

    # Extract the device ID and name from the device argument
    # device_id = device.split("!")[0] if len(device.split("!")) > 1 else None
    # device_name = device.split("!")[1] if len(device.split("!")) > 1 else device

    # # If the device ID is not found, return the device name
    # if not device_id:
    #     return device_name

    # Get the traces for the device from the pathlookup_decisions data
    if first_edge and not device_id:
        pattern = r"vDevice/(\d+)"
        match = re.search(pattern, edge)
        if match:
            device_id = match[0]
    if device_id:
        traces = [
            trace["trace"]
            for trace in pathlookup_decisions[device_id]["traces"]
            if trace["sourcePacketId"] == edge
        ] or [
            trace["trace"]
            for trace in pathlookup_decisions[device_id]["traces"]
            if trace["targetPacketId"] == edge
        ]
        security_info = ""
        security_info = get_security_traces(traces, security_info)
        protocol_info = get_protocol_traces(traces)
        device_info = f" | {protocol_info}"
        if security_info:
            device_info += f" | {security_info}"

        # If no security events are found, return the device name
        return device_info
    return ""

def display_path(
    path: list,
    details=False,
    pathlookup_decisions=None,
    zonefw_interfaces=None,
    l2_exclusion=False,
    output_table=None,
):
    """
    Build a graph list from the provided path and display it as a table or list.

    :param path: Path to display
    :param details: Flag for displaying detailed edge information
    :param pathlookup_decisions: Dictionary containing path decisions
    :param zonefw_interfaces: Dictionary containing zone firewall interfaces
    :param l2_exclusion: Flag to remove L2 info from the path
    :param table_display: Flag indicating whether to display the graph list as a table.

    Returns:
    - None
    """

    # Define the function building the table to display if the function
    def build_table(graph_list: list, output_table: Table):
        """
        Build a table from the provided graph list and output table.

        Parameters:
        - graph_list (list): A list containing graph data.
        - output_table (Table): The output table object to populate.

        Returns:
        - Table: The updated output table object.
        """
        output_table.add_column("Ingress Interface")
        output_table.add_column("Device", style="cyan", no_wrap=True)
        output_table.add_column("Egress Interface")
        output_table.add_column("Protocol", style="green")
        output_table.add_column("Security")
        output_table.add_column("Rule Chain")
        output_table.add_column("ZoneFW")

        for line in graph_list:
            line_info = line.split("|")
            output_table.add_row(*line_info)
        return output_table

    # Define a function to remove the entries as per the exclusion
    def remove_exclusion_protocol(graph_list: list, l2_exclusion: bool):
        """
        Removes entries from the graph_list based on the given exclusion criteria.

        :param graph_list: List representing the graph data
        :param l2_exclusion: Flag to remove L2 info from the path
        :return: A modified list with the specified entries removed
        """
        result = []
        exclusion = "l2/fp" if l2_exclusion else ""
        for i, entry in enumerate(graph_list):
            if 0 < i < len(graph_list) - 1:
                if (
                    all(protocol not in entry for protocol in L2_EXCLUSION_PROTOCOL)
                    or "security" in entry
                ) and not entry.startswith(" |"):
                    # Add the entry if it doesn't meet the exclusion criteria and is not an interface
                    result.append(entry)
                elif not entry.startswith(" |"):
                    if (
                        result[-1]
                        != f"... | ...{exclusion} skipped... | ... | {exclusion}"
                    ):
                        result.append(
                            f"... | ...{exclusion} skipped... | ... | {exclusion}"
                        )
            else:
                result.append(entry)
                # Add the last entry as is

        return result

    def build_graph(path):
        """
        builds a graph representation of a given path.

        Args:
            path (list): The list of edges representing the path.

        Returns:
            list: A list containing the summarized decisions to display.
        """
        output_list = []
        for row, edge in enumerate(path):
            device_info = ""
            components = edge.split("--")
            (src_info, src_device_id) = remove_vdevice_id(
                components[0], return_device_id=True
            )
            src_device_name = (
                src_info.split("@")[0] if len(src_info.split("@")) > 1 else src_info
            )
            egress_iface = (
                src_info.split("@")[1] if len(src_info.split("@")) > 1 else "-"
            )

            (dst_info, dst_device_id) = (
                remove_vdevice_id(components[1], return_device_id=True)
                if len(components) > 1
                else ("0", "0")
            )
            dst_device_name = (
                dst_info.split("@")[0] if len(dst_info.split("@")) > 1 else dst_info
            )
            ingress_iface = (
                dst_info.split("@")[1] if len(dst_info.split("@")) > 1 else "-"
            )

            # starting point
            if row == 0:
                device_info = f"- | {src_device_name} | {egress_iface}"
                device_details = get_edge_details(
                    pathlookup_decisions=pathlookup_decisions,
                    device_name=src_device_name,
                    device_id=src_device_id,
                    egress=egress_iface,
                    first_edge=True,
                    edge=edge,
                    zonefw_interfaces=zonefw_interfaces,
                )
                device_info += device_details
                output_list.append(device_info)

            if row < len(path) - 1:
                next_edge = path[row + 1]
                next_components = next_edge.split("--")
                next_src_info = remove_vdevice_id(next_components[0])
                next_src_device_name = (
                    next_src_info.split("@")[0]
                    if len(next_src_info.split("@")) > 1
                    else next_src_info
                )
                egress_iface = (
                    next_src_info.split("@")[1]
                    if len(next_src_info.split("@")) > 1
                    else "-"
                )
                if next_src_device_name != dst_device_name:
                    print(
                        f"WEIRD, those should be the same: {src_device_name} != {dst_device_name}"
                    )
                device_info = f"{ingress_iface} | {dst_device_name} | {egress_iface}"
            elif row == len(path) - 1:
                device_info = f"{ingress_iface} | {dst_device_name} | -"
            if details:
                device_details = get_edge_details(
                    pathlookup_decisions=pathlookup_decisions,
                    device_name=dst_device_name,
                    device_id=dst_device_id,
                    egress=egress_iface,
                    first_edge=False,
                    edge=edge,
                    zonefw_interfaces=zonefw_interfaces,
                )
                device_info += device_details
            output_list.append(device_info)

        return output_list

    graph_list = build_graph(path)
    if l2_exclusion:
        temp_graph_list = remove_exclusion_protocol(graph_list, l2_exclusion)
        if output_table:
            output_table = build_table(temp_graph_list, output_table)
            print(output_table)
        else:
            print(temp_graph_list)
    else:
        if output_table:
            output_table = build_table(graph_list, output_table)
            print(output_table)
        else:
            print(graph_list)
